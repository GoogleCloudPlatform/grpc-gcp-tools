#!/usr/bin/env python3
# Copyright 2022 gRPC authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Run one gRPC Observability integration tests test case"""

import argparse
import base64
from datetime import datetime, timezone
from enum import Enum
from google.cloud import (
    logging_v2,
    monitoring_v3,
    trace_v1,
)
from google.cloud.logging_v2.types import LogEntry
from google.cloud.monitoring_v3.types.metric_service import ListTimeSeriesResponse
from google.cloud.trace_v1.services.trace_service.pagers import ListTracesPager
from google.cloud.trace_v1.types import ListTracesResponse
from google.protobuf.timestamp_pb2 import Timestamp
from kubernetes import ( # type: ignore
    client as kubernetes_client,
    config as kubernetes_config,
    utils as kubernetes_utils,
)
from kubernetes.stream import stream as kubernetes_stream # type: ignore
import logging
import os
import random
import re
import signal
import string
import subprocess
import sys
from test_utils import (
    ConfigLocation,
    ExpectCount,
    InteropAction,
    JobMode,
    LoggerSide,
    ObservabilityConfig,
    ObservabilityTestCase,
    SupportedLang,
    SupportedLangEnum,
    TestRunMetadata,
    TestUtil,
)
import time
import traceback
from typing import Any, Dict, List, Optional, TextIO, Tuple, TypeVar, Type
import unittest

PROJECT = 'microsvcs-testing'
PROJECT_NUM = '168376032566'
CLUSTER_NAME = 'grpc-o11y-integration-testing-cluster'
GKE_NAMESPACE = 'grpc-o11y-integration-test-ns'
ZONE = 'us-central1-c'
OBSERVABILITY_LOG_NAME = 'microservices.googleapis.com%2Fobservability%2Fgrpc'
CONFIG_ENV_VAR_NAME = 'GRPC_GCP_OBSERVABILITY_CONFIG'
CONFIG_FILE_ENV_VAR_NAME = 'GRPC_GCP_OBSERVABILITY_CONFIG_FILE'
CONFIG_FILE_LOCAL_DIR = '/tmp'
SUPPORTED_METRICS = [
    'custom.googleapis.com/opencensus/grpc.io/client/started_rpcs',
    'custom.googleapis.com/opencensus/grpc.io/client/completed_rpcs',
    'custom.googleapis.com/opencensus/grpc.io/client/roundtrip_latency',
    'custom.googleapis.com/opencensus/grpc.io/client/sent_compressed_message_bytes_per_rpc',
    'custom.googleapis.com/opencensus/grpc.io/client/received_compressed_message_bytes_per_rpc',
    'custom.googleapis.com/opencensus/grpc.io/client/api_latency',
    'custom.googleapis.com/opencensus/grpc.io/server/started_rpcs',
    'custom.googleapis.com/opencensus/grpc.io/server/completed_rpcs',
    'custom.googleapis.com/opencensus/grpc.io/server/sent_compressed_message_bytes_per_rpc',
    'custom.googleapis.com/opencensus/grpc.io/server/received_compressed_message_bytes_per_rpc',
    'custom.googleapis.com/opencensus/grpc.io/server/server_latency',
]
# number of seconds to allow running RPC action command
WAIT_SECS_CLIENT_ACTION = 95
WAIT_SECS_SERVER_START = 40
WAIT_SECS_GKE_DEPLOYMENT = 150
WAIT_SECS_READY = 20

logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
formatter = logging.Formatter(fmt='%(asctime)s: %(levelname)-8s %(message)s')
console_handler.setFormatter(formatter)
logger.handlers = []
logger.addHandler(console_handler)
logger.setLevel(logging.DEBUG)

def parse_args() -> argparse.Namespace:
    argp = argparse.ArgumentParser(description='Run Observability integration tests')
    argp.add_argument('--server_lang', required=True, type=lambda s:SupportedLang(s),
                      help='Server language')
    argp.add_argument('--client_lang', required=True, type=lambda s:SupportedLang(s),
                      help='Client language')
    argp.add_argument('--job_mode', required=True, type=lambda s:JobMode(s),
                      help='Job mode')
    argp.add_argument('--test_case', required=True, type=lambda s:ObservabilityTestCase(s),
                      help='Test case to run')
    argp.add_argument('--port', required=False, default='',
                      help='Port number TestService server should run on')
    argp.add_argument('--gke_resource_identifier', required=False, default='',
                      help='GKE resource identifier, most likely a suffix')
    args = argp.parse_args()
    logger.debug('Parsed args: ' + str({k: str(v) for k, v in vars(args).items()}))
    return args

class CommonUtil:
    @staticmethod
    def get_image_name(lang: SupportedLang, job_mode: JobMode) -> str:
        image_name = os.environ.get('OBSERVABILITY_TEST_IMAGE_%s' % str(lang).upper(), '')
        if not image_name:
            raise Exception('No docker image for %s is found' % lang)
        return image_name

class TestRunner:
    args: argparse.Namespace
    job_name: str
    exc: Optional[Exception]

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.job_name = '%s:%s:%s' % (self.args.server_lang,
                                      self.args.client_lang,
                                      self.args.test_case)
        self.exc = None

    def write_sponge_xml(self) -> None:
        sponge_dir = TestUtil.get_sponge_log_dir(self.args.job_mode, self.job_name)
        with open(os.path.join(sponge_dir, 'sponge_log.xml'), 'w') as f:
            f.write(str(self))

    def __str__(self) -> str:
        timestamp = datetime.now(timezone.utc).isoformat()
        res = '<testsuites>\n'
        res += '  <testsuite errors="0" failures="%d" name="grpc-o11y-%s" ' % (
            (1 if self.exc else 0), self.job_name)
        res += 'package="grpc-o11y-tests" timestamp="%s">\n' % timestamp
        res += '  </testsuite>\n</testsuites>'
        return res

    def run(self) -> None:
        try:
            # TODO(stanleycheung): better structure these class to remove passing self
            impl = TestCaseImpl(self)
            test_case_func = getattr(impl, str(self.args.test_case))
            logger.info('Executing TestCaseImpl.%s()' % self.args.test_case)
            test_case_func()
            impl.sponge_log_out.close()
        except Exception as e:
            self.exc = e
            logger.error(traceback.format_exc())
        finally:
            self.write_sponge_xml()
            logger.info("Test case '%s' %s." % (self.args.test_case,
                                             'failed' if self.exc else 'passed'))
            if self.exc:
                raise self.exc

TestCaseImplT = TypeVar('TestCaseImplT', bound='TestCaseImpl')
CloudLoggingInterfaceT = TypeVar('CloudLoggingInterfaceT', bound='CloudLoggingInterface')
CloudMonitoringInterfaceT = TypeVar('CloudMonitoringInterfaceT', bound='CloudMonitoringInterface')
CloudTraceInterfaceT = TypeVar('CloudTraceInterfaceT', bound='CloudTraceInterface')

class CloudLoggingInterface(unittest.TestCase):
    EVENT_TYPES = ['CLIENT_HEADER', 'CLIENT_MESSAGE', 'SERVER_HEADER', 'SERVER_MESSAGE']
    results: List[LogEntry]

    @classmethod
    def query_logging_entries_from_cloud(cls: Type[CloudLoggingInterfaceT],
                                         test_impl: TestCaseImplT) -> CloudLoggingInterfaceT:
        logging_client = logging_v2.Client()
        logging_client.setup_logging()
        cloud_logger = logging_client.logger(OBSERVABILITY_LOG_NAME)
        filter_str = f'labels.identifier = "{test_impl.identifier}"'
        logger.info('Querying log entries: filter_str = %s' % filter_str)
        logging_entries = cloud_logger.list_entries(filter_ = filter_str)
        return cls(logging_entries)

    def __init__(self, results) -> None:
        super().__init__()
        self.results = list(results)
        logger.debug('Found %d log entries' % len(self.results))

    def count_total(self) -> int:
        return len(self.results)

    def count_with_type(self, event_type: str) -> int:
        return sum(1 for t in self.results if t.payload['type'] == event_type)

    def count_with_type_logger_method_name(self,
                                           event_type: str,
                                           logger_side: LoggerSide,
                                           method_name: str) -> int:
        return sum(1 for t in self.results if t.payload['type'] == event_type and
                   t.payload['logger'] == str(logger_side) and t.payload['methodName'] == method_name)

    def test_log_entries_zero(self) -> None:
        num_log_entries = self.count_total()
        self.assertEqual(num_log_entries, 0)

    def test_log_entries_at_least_one(self) -> None:
        num_log_entries = self.count_total()
        self.assertGreater(num_log_entries, 0)

    def test_event_type_at_least_one(self) -> None:
        for event_type in self.EVENT_TYPES:
            logger.debug('testing logging event %s' % event_type)
            self.assertGreater(self.count_with_type(event_type), 0)

    def test_log_entry_count(self,
                             logger_side: LoggerSide,
                             event_type: str,
                             method_name: str,
                             expect_num_entries: int) -> None:
        num = self.count_with_type_logger_method_name(event_type, logger_side, method_name)
        self.assertEqual(num, expect_num_entries)

    def test_method_entry_count(self,
                                logger_side: LoggerSide,
                                method_name: str,
                                expect_count: ExpectCount) -> None:
        for event_type in self.EVENT_TYPES:
            num = self.count_with_type_logger_method_name(event_type, logger_side, method_name)
            logger.debug('Testing %-15s %s %-15s: found %d log entries' %
                         (event_type, logger_side, method_name, num))
            if expect_count == ExpectCount.ZERO:
                self.assertEqual(num, 0)
            else:
                self.assertGreater(num, 0)

    def test_header_content(self,
                            logger_side: LoggerSide,
                            event_type: str,
                            expect_num_entries: int) -> None:
        logger.debug('Found these headers in log entries payload')
        for t in self.results:
            if t.payload['type'] in event_type and t.payload['logger'] == str(logger_side):
                if 'metadata' in t.payload['payload']:
                    metadata_payload = t.payload['payload']['metadata']
                else:
                    metadata_payload = t.payload['payload']
                logger.debug('%s %s: %d %s' % (t.payload['logger'], t.payload['type'],
                                               len(metadata_payload), metadata_payload))
                self.assertTrue(len(metadata_payload) >= expect_num_entries and \
                                len(metadata_payload) <= (expect_num_entries + 1))

    def test_message_content(self, logger_side: LoggerSide, expect_length: int) -> None:
        for t in self.results:
            if t.payload['logger'] == str(logger_side) and \
               t.payload['type'] in ['CLIENT_MESSAGE', 'SERVER_MESSAGE']:
                self.assertEqual(len(base64.b64decode(t.payload['payload']['message'])),
                                 expect_length)
                self.assertTrue(t.payload['payloadTruncated'])

    def test_custom_labels(self, logger_side: LoggerSide, expected_labels: Dict[str, str]) -> None:
        logger.debug('Looking at logging entries custom labels')
        for t in self.results:
            if t.payload['logger'] == str(logger_side):
                logger.debug('%s: %s %s' % (t.payload['logger'], t.payload['type'], str(t.labels)))
                self.assertEqual(t.labels, {**t.labels, **expected_labels})

class CloudMonitoringInterface(unittest.TestCase):
    results: Dict[str, List[ListTimeSeriesResponse]]

    @classmethod
    def query_metrics_from_cloud(cls: Type[CloudMonitoringInterfaceT],
                                 test_impl: TestCaseImplT) -> CloudMonitoringInterfaceT:
        metric_client = monitoring_v3.MetricServiceClient()
        interval = monitoring_v3.TimeInterval({
            'end_time': {'seconds': int(time.time()),
                         'nanos': test_impl.test_run_metadata.nanos},
            'start_time': {'seconds': test_impl.test_run_metadata.test_case_start_seconds,
                           'nanos': test_impl.test_run_metadata.nanos},
        })
        metrics_results: Dict[str, List[ListTimeSeriesResponse]] = {}
        for metric_name in SUPPORTED_METRICS:
            if 'client' in metric_name:
                method_label = 'grpc_client_method'
            elif 'server' in metric_name:
                method_label = 'grpc_server_method'
            else:
                raise Exception('Unexpected metric name: %s' % metric_name)
            # cloud monitoring API only allows querying one metric at a time
            filter_str = ('metric.type = "%s" AND metric.labels.identifier = "%s" ' \
                          'AND metric.labels.%s = starts_with("grpc.testing.TestService")'
                          % (metric_name, test_impl.identifier, method_label))
            logger.info('Querying list_time_series: %s' % filter_str)
            time_series = metric_client.list_time_series(
                name=f'projects/{PROJECT}',
                filter=filter_str,
                interval=interval,
            )
            metrics_results[metric_name] = []
            for series in time_series:
                metrics_results[metric_name].append(series)
            logger.debug('Found %d time_series for %s' % (
                len(metrics_results[metric_name]), metric_name))
        return cls(metrics_results)

    def __init__(self, results: Dict[str, List[ListTimeSeriesResponse]]) -> None:
        super().__init__()
        self.results = results

    # TODO(stanleycheung): look to replace this with copy.deepcopy()
    def copy_to_dict(self, obj: Dict) -> Dict:
        return {key: value for key, value in obj.items()}

    def count_total(self, metric_name: str) -> int:
        return len(self.results[metric_name])

    def test_time_series_zero(self, metric_name: str) -> None:
        num_metrics_result = self.count_total(metric_name)
        self.assertEqual(num_metrics_result, 0)

    def test_time_series_at_least_one(self, metric_name: str) -> None:
        num_metrics_result = self.count_total(metric_name)
        self.assertGreater(num_metrics_result, 0)

    def test_metric_resource_type(self, metric_name: str, resource_type: str) -> None:
        for result in self.results[metric_name]:
            self.assertEqual(result.resource.type, resource_type)

    def test_metric_resource_labels(self, metric_name: str, resource_labels: Dict[str, str]) -> None:
        for result in self.results[metric_name]:
            logger.debug('Metric resource labels: %s' % str(result.resource.labels.items()))
            actual_labels = self.copy_to_dict(result.resource.labels)
            self.assertEqual(actual_labels, {**actual_labels, **resource_labels})

    def test_metric_labels(self, metric_name: str, expected_labels: Dict[str, str]) -> None:
        logger.debug('Looking at metric custom labels for %s' % metric_name)
        for result in self.results[metric_name]:
            logger.debug(str(result.metric.labels))
            actual_labels = self.copy_to_dict(result.metric.labels)
            self.assertEqual(actual_labels, {**actual_labels, **expected_labels})

    def test_metrics_basic(self, num_rpcs: int) -> None:
        for metric_name in [
            'custom.googleapis.com/opencensus/grpc.io/client/started_rpcs',
            'custom.googleapis.com/opencensus/grpc.io/client/completed_rpcs',
            'custom.googleapis.com/opencensus/grpc.io/server/started_rpcs',
            'custom.googleapis.com/opencensus/grpc.io/server/completed_rpcs',
        ]:
            logger.info('%s %d' % (metric_name, self.results[metric_name][0].points[0].value.int64_value))
            self.assertEqual(self.results[metric_name][0].points[0].value.int64_value, num_rpcs)

    def test_metrics_latency(self) -> None:
        for metric_name in [
            'custom.googleapis.com/opencensus/grpc.io/client/roundtrip_latency',
            'custom.googleapis.com/opencensus/grpc.io/client/api_latency',
            'custom.googleapis.com/opencensus/grpc.io/server/server_latency',
        ]:
            logger.info('%s %.2f' %
                        (metric_name,
                         self.results[metric_name][0].points[0].value.distribution_value.mean))
            self.assertGreater(self.results[metric_name][0].points[0].value.distribution_value.mean, 0)
        # per attempt latency
        metric_name = 'custom.googleapis.com/opencensus/grpc.io/client/roundtrip_latency'
        roundtrip_latency = self.results[metric_name][0].points[0].value.distribution_value.mean
        # per call latency
        metric_name = 'custom.googleapis.com/opencensus/grpc.io/client/api_latency'
        api_latency = self.results[metric_name][0].points[0].value.distribution_value.mean
        # per attempt latency should be less than per call latency
        self.assertLess(roundtrip_latency, api_latency)

    def test_metrics_message_bytes(self) -> None:
        for metric_name in [
            'custom.googleapis.com/opencensus/grpc.io/client/sent_compressed_message_bytes_per_rpc',
            'custom.googleapis.com/opencensus/grpc.io/client/received_compressed_message_bytes_per_rpc',
            'custom.googleapis.com/opencensus/grpc.io/server/sent_compressed_message_bytes_per_rpc',
            'custom.googleapis.com/opencensus/grpc.io/server/received_compressed_message_bytes_per_rpc',
        ]:
            logger.info('%s %.2f' %
                        (metric_name,
                         self.results[metric_name][0].points[0].value.distribution_value.mean))
            # TODO(stanleycheung): improve this assertion to be more specific
            self.assertGreater(self.results[metric_name][0].points[0].value.distribution_value.mean, 0)

class CloudTraceInterface(unittest.TestCase):
    TESTING_SPAN_PREFIX = 'grpc.testing.TestService'
    SENT_SPAN_PREFIX = ('Sent.%s' % TESTING_SPAN_PREFIX)
    RECV_SPAN_PREFIX = ('Recv.%s' % TESTING_SPAN_PREFIX)
    results: List[ListTracesResponse]

    @classmethod
    def query_traces_from_cloud(cls: Type[CloudTraceInterfaceT],
                                test_impl: TestCaseImplT) -> CloudTraceInterfaceT:
        trace_client = trace_v1.TraceServiceClient()
        filter_str = '+identifier:%s' % test_impl.identifier
        logger.info('Querying traces: filter_str = %s' % filter_str)
        request = trace_v1.ListTracesRequest(
            project_id=PROJECT,
            start_time=Timestamp(seconds=test_impl.test_run_metadata.test_case_start_seconds),
            view=trace_v1.ListTracesRequest.ViewType.COMPLETE,
            filter=filter_str
        )
        trace_results = trace_client.list_traces(request=request)
        return cls(trace_results)

    def __init__(self, results: ListTracesPager) -> None:
        super().__init__()
        self.results = []
        for trace_response in results:
            for span in trace_response.spans:
                if self.TESTING_SPAN_PREFIX in span.name:
                    self.results.append(trace_response)
                    break
        logger.debug('Found %d traces' % len(self.results))

    def print_basic_debug(self) -> None:
        for trace in self.results:
            logger.info('Found trace_id %s' % trace.trace_id)
            for span in trace.spans:
                logger.info('  Found span %s' % span.name)

    def copy_to_dict(self, obj: Dict) -> Dict:
        return {key: value for key, value in obj.items()}

    def count_total(self) -> int:
        return len(self.results)

    def has_sent_span(self) -> bool:
        for trace_response in self.results:
            for span in trace_response.spans:
                if self.SENT_SPAN_PREFIX in span.name:
                    return True
        return False

    def has_recv_span(self) -> bool:
        for trace_response in self.results:
            for span in trace_response.spans:
                if self.RECV_SPAN_PREFIX in span.name:
                    return True
        return False

    def test_trace_at_least_one(self) -> None:
        num_traces = self.count_total()
        self.assertGreater(num_traces, 0)

    def test_trace_sent_span_exists(self) -> None:
        self.assertTrue(self.has_sent_span())

    def test_trace_recv_span_exists(self) -> None:
        self.assertTrue(self.has_recv_span())

    def test_trace_zero_sent_span(self) -> None:
        self.assertFalse(self.has_sent_span())

    def test_trace_zero_recv_span(self) -> None:
        self.assertFalse(self.has_recv_span())

    def test_traces_count(self, num_traces: int) -> None:
        self.assertEqual(self.count_total(), num_traces,
                         'Expect %d traces. Found %d instead' % (
                             num_traces, self.count_total()))

    def test_traces_count_range(self, lower_bound: int, upper_bound: int) -> None:
        num_traces = self.count_total()
        self.assertTrue(num_traces >= lower_bound and num_traces <= upper_bound)

    def test_span_custom_labels(self,
                                span_name_prefix: str,
                                expected_labels: Dict[str, str]) -> None:
        logger.debug('Looking at trace spans labels')
        for trace_response in self.results:
            for span in trace_response.spans:
                logger.debug('%s %s %s' % (trace_response.trace_id, span.name, str(span.labels)))
                if span_name_prefix in span.name:
                    actual_labels = self.copy_to_dict(span.labels)
                    self.assertEqual(actual_labels, {**actual_labels, **expected_labels})

class TestCaseImpl(unittest.TestCase):
    test_runner: TestRunner
    args: argparse.Namespace
    identifier: str
    test_run_metadata: TestRunMetadata
    server_config: ObservabilityConfig
    client_config: ObservabilityConfig
    sponge_log_out: TextIO

    def __init__(self,
                 test_runner: TestRunner) -> None:
        self.test_runner = test_runner
        self.args = test_runner.args
        self.test_run_metadata = TestRunMetadata()
        self.initialize_config()
        sponge_log_file = os.path.join(TestUtil.get_sponge_log_dir(
            self.args.job_mode, self.test_runner.job_name), 'sponge_log.log')
        self.sponge_log_out = open(sponge_log_file, 'a')
        # TODO(stanleycheung): generalize this when we added back GKE tests
        self.RESOURCE_TYPE = 'k8s_container'
        if os.environ.get('RESOURCE_TYPE_ASSERTION_OVERRIDE'):
            self.RESOURCE_TYPE = str(os.environ.get('RESOURCE_TYPE_ASSERTION_OVERRIDE'))

    def initialize_config(self) -> None:
        self.identifier = self.generate_identifier()
        self.server_config = ObservabilityConfig({
            'project_id': PROJECT,
            'labels': {
                'grpc_server': 'true',
                'test_case': self.args.test_case,
                'identifier': self.identifier
            }
        })
        self.client_config = ObservabilityConfig({
            'project_id': PROJECT,
            'labels': {
                'grpc_client': 'true',
                'test_case': self.args.test_case,
                'identifier': self.identifier
            }
        })

    def enable_server_logging(self, method_filters: Optional[List] = None) -> None:
        self.server_config.setdefault('cloud_logging', {})
        self.server_config.set('cloud_logging', {'server_rpc_events': {}})
        default = [{
            'methods': ['*'],
            'max_metadata_bytes': 4096,
            'max_message_bytes': 4096
        }]
        if method_filters:
            self.server_config.set('cloud_logging', {'server_rpc_events': method_filters})
        else:
            self.server_config.set('cloud_logging', {'server_rpc_events': default})

    def enable_client_logging(self, method_filters: Optional[List] = None) -> None:
        self.client_config.setdefault('cloud_logging', {})
        self.client_config.set('cloud_logging', {'client_rpc_events': {}})
        default = [{
            'methods': ['*'],
            'max_metadata_bytes': 4096,
            'max_message_bytes': 4096
        }]
        if method_filters:
            self.client_config.set('cloud_logging', {'client_rpc_events': method_filters})
        else:
            self.client_config.set('cloud_logging', {'client_rpc_events': default})

    def enable_server_monitoring(self) -> None:
        self.server_config.setdefault('cloud_monitoring', {})

    def enable_client_monitoring(self) -> None:
        self.client_config.setdefault('cloud_monitoring', {})

    def enable_server_trace(self, trace_config: Optional[Dict[str, Any]] = None) -> None:
        self.server_config.setdefault('cloud_trace', {})
        default = {
            'sampling_rate': 1.0
        }
        if trace_config:
            self.server_config.set('cloud_trace', trace_config)
        else:
            self.server_config.set('cloud_trace', default)

    def enable_client_trace(self, trace_config: Optional[Dict[str, Any]] = None) -> None:
        self.client_config.setdefault('cloud_trace', {})
        default = {
            'sampling_rate': 1.0
        }
        if trace_config:
            self.client_config.set('cloud_trace', trace_config)
        else:
            self.client_config.set('cloud_trace', default)

    def enable_all_config(self) -> None:
        self.enable_server_logging()
        self.enable_client_logging()
        self.enable_server_monitoring()
        self.enable_client_monitoring()
        self.enable_server_trace()
        self.enable_client_trace()

    def set_server_custom_labels(self, custom_labels: Dict[str, str]) -> None:
        self.server_config.set('labels', custom_labels)

    def set_client_custom_labels(self, custom_labels: Dict[str, str]) -> None:
        self.client_config.set('labels', custom_labels)

    @staticmethod
    def generate_identifier() -> str:
        identifier = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        identifier += datetime.now(timezone.utc).strftime('%y%m%d%H%M%S')
        logger.info('Generated identifier: %s' % identifier)
        return identifier

    def get_server_start_cmd(self) -> str:
        return 'docker run -e %s -e %s -v %s:%s %s --name %s %s server --port=%s' % (
            CONFIG_FILE_ENV_VAR_NAME,
            CONFIG_ENV_VAR_NAME,
            CONFIG_FILE_LOCAL_DIR,
            CONFIG_FILE_LOCAL_DIR,
            os.environ.get('CUSTOM_DOCKER_RUN_AUTH', ''),
            self.get_server_container_name(),
            CommonUtil.get_image_name(self.args.server_lang, self.args.job_mode),
            self.args.port)

    def get_client_action_cmd(self, action: InteropAction) -> str:
        server_container_name = self.get_server_container_name()
        return 'docker run --rm -e %s -e %s -v %s:%s %s --link %s:%s %s client ' \
          '--server_host=%s --server_port=%s ' \
          '--test_case=%s --num_times=%d' % (
              CONFIG_FILE_ENV_VAR_NAME,
              CONFIG_ENV_VAR_NAME,
              CONFIG_FILE_LOCAL_DIR,
              CONFIG_FILE_LOCAL_DIR,
              os.environ.get('CUSTOM_DOCKER_RUN_AUTH', ''),
              server_container_name,
              server_container_name,
              CommonUtil.get_image_name(self.args.client_lang, self.args.job_mode),
              server_container_name,
              self.args.port,
              action.test_case,
              action.num_times)

    @staticmethod
    def wait_before_querying_o11y_data() -> None:
        logger.info('Wait %d seconds before querying cloud...' % WAIT_SECS_READY)
        time.sleep(WAIT_SECS_READY)

    @staticmethod
    def get_env_with_config(config: ObservabilityConfig,
                            config_file_name: Optional[str] = None) -> Dict[str, Any]:
        env = os.environ.copy()
        if config_file_name:
            config_file_path = '%s/%s' % (CONFIG_FILE_LOCAL_DIR, config_file_name)
            with open(config_file_path, 'w') as f:
                logger.debug('Writing config to file %s: %s' % (config_file_path, config.toJson()))
                f.write(config.toJson())
            env[CONFIG_FILE_ENV_VAR_NAME] = config_file_path
        else:
            env[CONFIG_ENV_VAR_NAME] = config.toJson()
        return env

    def get_server_container_name(self) -> str:
        return 'observability-test-server-%s' % self.identifier

    def start_server_in_subprocess(self, env: Optional[Dict[str, Any]] = None) -> subprocess.Popen:
        server_start_cmd = self.get_server_start_cmd()
        logger.info('Starting server at port %s...' % self.args.port)
        logger.info(server_start_cmd)
        logger.info('Server container logs are being written to: %s' % self.sponge_log_out.name)
        server_proc = subprocess.Popen(server_start_cmd.split(),
                                       stdout=self.sponge_log_out,
                                       stderr=self.sponge_log_out,
                                       env=env)
        return server_proc

    def start_client_in_subprocess(self,
                                   action: InteropAction,
                                   env: Optional[Dict[str, Any]] = None) -> subprocess.Popen:
        client_action_cmd = self.get_client_action_cmd(action)
        logger.info('Running client cmd: %s' % client_action_cmd)
        logger.info('Client container logs are being written to: %s' % self.sponge_log_out.name)
        client_proc = subprocess.Popen(client_action_cmd.split(),
                                       stdout=self.sponge_log_out,
                                       stderr=self.sponge_log_out,
                                       env=env)
        return client_proc

    def kill_server_docker_container(self) -> None:
        docker_kill_cmd = 'docker rm -f %s' % self.get_server_container_name()
        subprocess.Popen(docker_kill_cmd.split(),
                         stdout=self.sponge_log_out,
                         stderr=self.sponge_log_out,
                         env=os.environ.copy())

    def setup_and_run_rpc(self,
                          actions: List[InteropAction],
                          config_location: ConfigLocation = ConfigLocation.FILE,
                          server_config_into_env_var: Optional[ObservabilityConfig] = None,
                          client_config_into_env_var: Optional[ObservabilityConfig] = None) -> None:
        self.gke_setup_and_run_rpc(actions)
        #                           config_location,
        #                           server_config_into_env_var,
        #                           client_config_into_env_var)

    def gce_setup_and_run_rpc(self,
                              actions: List[InteropAction],
                              config_location: ConfigLocation = ConfigLocation.FILE,
                              server_config_into_env_var: Optional[ObservabilityConfig] = None,
                              client_config_into_env_var: Optional[ObservabilityConfig] = None) -> None:
        if config_location == ConfigLocation.FILE:
            server_env = self.get_env_with_config(
                self.server_config,
                config_file_name = 'server-config-%s.json' % self.identifier)
            client_env = self.get_env_with_config(
                self.client_config,
                config_file_name = 'client-config-%s.json' % self.identifier)
        elif config_location == ConfigLocation.ENV_VAR:
            server_env = self.get_env_with_config(self.server_config)
            client_env = self.get_env_with_config(self.client_config)
        else:
            raise Exception('Unhandled ConfigLocation enum value')
        if server_config_into_env_var:
            server_env[CONFIG_ENV_VAR_NAME] = server_config_into_env_var.toJson()
        if client_config_into_env_var:
            client_env[CONFIG_ENV_VAR_NAME] = client_config_into_env_var.toJson()
        server_proc = self.start_server_in_subprocess(env = server_env)
        time.sleep(WAIT_SECS_SERVER_START)
        exc = None
        try:
            client_procs = []
            for action in actions:
                client_procs.append(self.start_client_in_subprocess(action, env = client_env))
            for client_proc in client_procs:
                client_proc.wait(timeout=WAIT_SECS_CLIENT_ACTION)
            self.wait_before_querying_o11y_data()
        except Exception as e:
            exc = e
            logger.error(traceback.format_exc())
        finally:
            logger.info('Killing server...')
            os.kill(server_proc.pid, signal.SIGKILL)
            self.kill_server_docker_container()
            server_proc.wait(timeout=5)
            if exc:
                raise exc

    def gke_initialize(self) -> None:
        logger.info('checking k8s config context')
        contexts, active_context = kubernetes_config.list_kube_config_contexts()
        if not contexts:
            raise Exception('Cannot find any context in kube-config file')
        for context in contexts:
            if CLUSTER_NAME in context['name']:
                logger.info(context)
                kubernetes_config.load_kube_config(context=context['name'])
                return
        raise Exception('No context for the right testing cluster was found')

    def gke_create_pod(self,
                       container_name: str,
                       pod_name: str,
                       config: ObservabilityConfig,
                       args: List[str],
                       labels: Dict[str, str] = {}) -> None:
        k8s_core_v1 = kubernetes_client.CoreV1Api()
        image_name = CommonUtil.get_image_name(self.args.client_lang, self.args.job_mode)
        logger.info('gke image name = %s' % image_name)
        container = kubernetes_client.V1Container(
            name=container_name,
            image=image_name,
            env=[kubernetes_client.V1EnvVar(name=CONFIG_ENV_VAR_NAME,
                                            value=config.toJson())],
            ports=[kubernetes_client.V1ContainerPort(container_port=9464)],
            args=args,
        )
        pod = kubernetes_client.V1Pod(
            metadata=kubernetes_client.V1ObjectMeta(
                name=pod_name,
                labels=labels,
            ),
            spec=kubernetes_client.V1PodSpec(
                containers=[container],
            ),
        )
        k8s_core_v1.create_namespaced_pod(GKE_NAMESPACE, pod)

    def gke_get_pod_ip(self, pod_name: str) -> str:
        k8s_core_v1 = kubernetes_client.CoreV1Api()
        pods = k8s_core_v1.list_namespaced_pod(GKE_NAMESPACE)
        for pod in pods.items:
            if pod.metadata.name == pod_name:
                return pod.status.pod_ip
        raise Exception('Pod not found')

    def gke_get_pod_status(self, pod_name: str) -> str:
        k8s_core_v1 = kubernetes_client.CoreV1Api()
        pods = k8s_core_v1.list_namespaced_pod(GKE_NAMESPACE)
        for pod in pods.items:
            if pod.metadata.name == pod_name:
                return pod.status.phase
        raise Exception('Pod not found')

    def gke_wait_for_pod_ready(self, pod_name: str) -> None:
        pod_status = ''
        wait_secs = 0
        while pod_status != 'Running':
            pod_status = self.gke_get_pod_status(pod_name)
            wait_secs += 1
            time.sleep(1)
            if wait_secs > WAIT_SECS_SERVER_START:
                raise Exception('timeout waiting for pod %s to be ready' % pod_name)

    def gke_wait_delete_pod(self, pod_names: List[str]) -> None:
        k8s_core_v1 = kubernetes_client.CoreV1Api()
        wait_secs = 0
        while True:
            pods = k8s_core_v1.list_namespaced_pod(GKE_NAMESPACE)
            num_pods_still_to_be_deleted = 0
            for pod in pods.items:
                if pod.metadata.name in pod_names:
                    num_pods_still_to_be_deleted += 1
            if num_pods_still_to_be_deleted > 0:
                time.sleep(1)
                wait_secs += 1
            else:
                break
            if wait_secs > 60:
                raise Exception('timeout waiting to delete all pods')

    def gke_setup_and_run_rpc(self,
                              actions: List[InteropAction]) -> None:
        self.gke_initialize()
        gke_identifier = self.generate_identifier()
        SERVER_CONTAINER_NAME = 'grpc-o11y-gke-server-ctnr-%s' % gke_identifier
        SERVER_POD_NAME = 'grpc-o11y-gke-server-pod-%s' % gke_identifier
        CLIENT_CONTAINER_NAME_BASE = 'grpc-o11y-gke-client-ctnr-%s'
        CLIENT_POD_NAME_BASE = 'grpc-o11y-gke-client-pod-%s'
        k8s_core_v1 = kubernetes_client.CoreV1Api()

        logger.info('Starting server pod')
        self.gke_create_pod(
            container_name=SERVER_CONTAINER_NAME,
            pod_name=SERVER_POD_NAME,
            config=self.server_config,
            args=['server', '--port=%s' % self.args.port],
        )

        logger.info('Waiting for server pod to get ready')
        self.gke_wait_for_pod_ready(SERVER_POD_NAME)

        logger.info('Querying server pod IP')
        server_ip = self.gke_get_pod_ip(SERVER_POD_NAME)
        logger.info(server_ip)

        logger.info('Starting client pods')
        client_pod_names = []
        for action in actions:
            client_action_identifier = self.generate_identifier()
            client_container_name = CLIENT_CONTAINER_NAME_BASE % client_action_identifier
            client_pod_name = CLIENT_POD_NAME_BASE % client_action_identifier
            self.gke_create_pod(
                container_name=client_container_name,
                pod_name=client_pod_name,
                config=self.client_config,
                args=['client',
                      '--server_host=%s' % server_ip,
                      '--server_port=%s' % self.args.port,
                      '--num_times=10',
                      '--test_case=%s' % action.test_case],
                labels={'app.kubernetes.io/name':'grpc-otel-observability-test'}
            )
            client_pod_names.append(client_pod_name)
            self.gke_wait_for_pod_ready(client_pod_name)

        logger.info('Waiting for client action to finish')
        for i in range(0, 6):
            logger.info('sleeping for 15 seconds')
            time.sleep(15)
            for client_pod_name in client_pod_names:
                logger.info('Querying client pod IP')
                client_ip = self.gke_get_pod_ip(client_pod_name)
                client_pod_status = self.gke_get_pod_status(client_pod_name)
                logger.info('%s %s %s' %(client_pod_name, client_ip, client_pod_status))
                logger.info('calling curl localhost:9464/metrics on %s', client_pod_name)
                resp = kubernetes_stream(k8s_core_v1.connect_get_namespaced_pod_exec,
                                         client_pod_name,
                                         GKE_NAMESPACE,
                                         command=['/bin/sh', '-c', 'curl localhost:9464/metrics'],
                                         stderr=True, stdin=False, stdout=True, tty=False)
                logger.info(resp);
                curl_command = 'curl http://%s:9464/metrics' % client_ip
                logger.info('calling %s on server %s' % (curl_command, SERVER_POD_NAME))
                resp = kubernetes_stream(k8s_core_v1.connect_get_namespaced_pod_exec,
                                         SERVER_POD_NAME,
                                         GKE_NAMESPACE,
                                         command=['/bin/sh', '-c', curl_command],
                                         stderr=True, stdin=False, stdout=True, tty=False)
                logger.info(resp);

        logger.info('Deleting server pod %s' % SERVER_POD_NAME)
        response = k8s_core_v1.delete_namespaced_pod(name=SERVER_POD_NAME,
                                                 namespace=GKE_NAMESPACE)

        for client_pod_name in client_pod_names:
            logger.info('Reading logs for pod %s' % client_pod_name)
            logs = k8s_core_v1.read_namespaced_pod_log(name=client_pod_name,
                                                       namespace=GKE_NAMESPACE)
            logger.info(logs)
            logger.info('Deleting client pod %s' % client_pod_name)
            response = k8s_core_v1.delete_namespaced_pod(name=client_pod_name,
                                                         namespace=GKE_NAMESPACE)

        logger.info('Waiting for pods to get deleted')
        self.gke_wait_delete_pod(client_pod_names + [SERVER_POD_NAME])

    def test_logging_basic(self) -> None:
        self.enable_server_logging()
        self.enable_client_logging()
        self.setup_and_run_rpc([InteropAction('large_unary')])
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_log_entries_at_least_one()
        logging_results.test_event_type_at_least_one()

    def test_monitoring_basic(self) -> None:
        self.enable_server_monitoring()
        self.enable_client_monitoring()
        self.setup_and_run_rpc([InteropAction('large_unary')])
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        for metric_name in SUPPORTED_METRICS:
            metrics_results.test_time_series_at_least_one(metric_name)
            metrics_results.test_metric_resource_type(metric_name, self.RESOURCE_TYPE)
            metrics_results.test_metric_resource_labels(metric_name, {
                'project_id': PROJECT,
            })

    def test_trace_basic(self) -> None:
        self.enable_server_trace()
        self.enable_client_trace()
        self.setup_and_run_rpc([InteropAction('large_unary')])
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_results.test_trace_at_least_one()
        trace_results.test_trace_sent_span_exists()
        trace_results.test_trace_recv_span_exists()

    def test_configs_disable_logging(self) -> None:
        self.setup_and_run_rpc([InteropAction('large_unary')])
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_log_entries_zero()

    def test_configs_disable_monitoring(self) -> None:
        self.setup_and_run_rpc([InteropAction('large_unary')])
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        for metric_name in SUPPORTED_METRICS:
            metrics_results.test_time_series_zero(metric_name)

    def test_configs_disable_trace(self) -> None:
        self.setup_and_run_rpc([InteropAction('large_unary')])
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_results.test_trace_zero_recv_span()
        trace_results.test_trace_zero_sent_span()

    def test_streaming(self) -> None:
        self.enable_all_config()
        self.setup_and_run_rpc([InteropAction('ping_pong')])
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_log_entries_at_least_one()
        logging_results.test_event_type_at_least_one()
        logging_results.test_log_entry_count(LoggerSide.SERVER, 'CLIENT_MESSAGE', 'FullDuplexCall', 4)
        logging_results.test_log_entry_count(LoggerSide.SERVER, 'SERVER_MESSAGE', 'FullDuplexCall', 4)
        logging_results.test_log_entry_count(LoggerSide.CLIENT, 'CLIENT_MESSAGE', 'FullDuplexCall', 4)
        logging_results.test_log_entry_count(LoggerSide.CLIENT, 'SERVER_MESSAGE', 'FullDuplexCall', 4)
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        for metric_name in SUPPORTED_METRICS:
            metrics_results.test_time_series_at_least_one(metric_name)
            metrics_results.test_metric_resource_type(metric_name, self.RESOURCE_TYPE)
            metrics_results.test_metric_resource_labels(metric_name, {
                'project_id': PROJECT
            })
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_results.test_trace_at_least_one()
        trace_results.test_trace_sent_span_exists()
        trace_results.test_trace_recv_span_exists()

    def test_configs_logging_service_filter(self) -> None:
        self.enable_server_logging([{
            'methods': ['grpc.testing.TestService/*'],
            'max_metadata_bytes': 4096,
            'max_message_bytes': 4096
        }])
        self.enable_client_logging([{
            'methods': ['grpc.testing.UnimplementedService/*'],
            'max_metadata_bytes': 4096,
            'max_message_bytes': 4096
        }])
        self.setup_and_run_rpc([InteropAction('large_unary'),
                                InteropAction('ping_pong')])
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_method_entry_count(LoggerSide.SERVER, 'UnaryCall',
                                                ExpectCount.AT_LEAST_ONE)
        logging_results.test_method_entry_count(LoggerSide.SERVER, 'FullDuplexCall',
                                                ExpectCount.AT_LEAST_ONE)
        logging_results.test_method_entry_count(LoggerSide.CLIENT, 'UnaryCall',
                                                ExpectCount.ZERO)
        logging_results.test_method_entry_count(LoggerSide.CLIENT, 'FullDuplexCall',
                                                ExpectCount.ZERO)

    def test_configs_logging_method_filter(self) -> None:
        self.enable_server_logging([{
            'methods': ['grpc.testing.TestService/UnaryCall'],
            'max_metadata_bytes': 4096,
            'max_message_bytes': 4096
        }])
        self.enable_client_logging([{
            'methods': ['grpc.testing.TestService/FullDuplexCall'],
            'max_metadata_bytes': 4096,
            'max_message_bytes': 4096
        }])
        self.setup_and_run_rpc([InteropAction('large_unary'),
                                InteropAction('ping_pong')])
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_method_entry_count(LoggerSide.SERVER, 'UnaryCall',
                                                ExpectCount.AT_LEAST_ONE)
        logging_results.test_method_entry_count(LoggerSide.SERVER, 'FullDuplexCall',
                                                ExpectCount.ZERO)
        logging_results.test_method_entry_count(LoggerSide.CLIENT, 'UnaryCall',
                                                ExpectCount.ZERO)
        logging_results.test_method_entry_count(LoggerSide.CLIENT, 'FullDuplexCall',
                                                ExpectCount.AT_LEAST_ONE)

    def test_configs_logging_exclude_filter(self) -> None:
        self.enable_server_logging([
            {
                'methods': ['grpc.testing.TestService/UnaryCall'],
                'exclude': True
            },
            {
                'methods': ['*'],
                'max_metadata_bytes': 4096,
                'max_message_bytes': 4096
            }
        ])
        self.enable_client_logging([
            {
                'methods': ['grpc.testing.TestService/FullDuplexCall'],
                'exclude': True
            },
            {
                'methods': ['*'],
                'max_metadata_bytes': 4096,
                'max_message_bytes': 4096
            }
        ])
        self.setup_and_run_rpc([InteropAction('large_unary'),
                                InteropAction('ping_pong')])
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_method_entry_count(LoggerSide.SERVER, 'UnaryCall',
                                                ExpectCount.ZERO)
        logging_results.test_method_entry_count(LoggerSide.SERVER, 'FullDuplexCall',
                                                ExpectCount.AT_LEAST_ONE)
        logging_results.test_method_entry_count(LoggerSide.CLIENT, 'UnaryCall',
                                                ExpectCount.AT_LEAST_ONE)
        logging_results.test_method_entry_count(LoggerSide.CLIENT, 'FullDuplexCall',
                                                ExpectCount.ZERO)

    def test_configs_logging_metadata_limit(self) -> None:
        self.enable_server_logging([{
            'methods': ['*'],
            'max_metadata_bytes': 60,
        }])
        self.enable_client_logging([{
            'methods': ['*'],
            'max_metadata_bytes': 60,
        }])
        self.setup_and_run_rpc([InteropAction('custom_metadata')])
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_header_content(LoggerSide.CLIENT, 'CLIENT_HEADER', 1)
        logging_results.test_header_content(LoggerSide.SERVER, 'CLIENT_HEADER', 1)

    def test_configs_logging_payload_limit(self) -> None:
        self.enable_server_logging([{
            'methods': ['*'],
            'max_message_bytes': 25,
        }])
        self.enable_client_logging([{
            'methods': ['*'],
            'max_message_bytes': 27,
        }])
        self.setup_and_run_rpc([InteropAction('large_unary')])
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_message_content(LoggerSide.SERVER, 25)
        logging_results.test_message_content(LoggerSide.CLIENT, 27)

    def test_configs_trace_sampling_rate(self) -> None:
        self.enable_server_trace({
            'sampling_rate': 0.50
        })
        self.enable_client_trace({
            'sampling_rate': 0.50
        })
        # Make 20 UnaryCall's
        self.setup_and_run_rpc([InteropAction('large_unary', num_times = 20)])
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        # With 50%, we should get 5-15 traces with 98.8% probability
        trace_results.test_traces_count_range(5, 15)

    def test_configs_env_var(self) -> None:
        self.enable_all_config()
        self.setup_and_run_rpc([InteropAction('large_unary')],
                               config_location = ConfigLocation.ENV_VAR)
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_log_entries_at_least_one()
        logging_results.test_event_type_at_least_one()
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        for metric_name in SUPPORTED_METRICS:
            metrics_results.test_time_series_at_least_one(metric_name)
            metrics_results.test_metric_resource_type(metric_name, self.RESOURCE_TYPE)
            metrics_results.test_metric_resource_labels(metric_name, {
                'project_id': PROJECT
            })
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_results.test_trace_at_least_one()
        trace_results.test_trace_sent_span_exists()
        trace_results.test_trace_recv_span_exists()

    def test_configs_file_over_env_var(self) -> None:
        self.enable_all_config()
        unused_server_config = ObservabilityConfig({
            'project_id': PROJECT,
            'labels': {
                'grpc_server': 'true',
                'identifier': self.identifier
            }
        })
        unused_client_config = ObservabilityConfig({
            'project_id': PROJECT,
            'labels': {
                'grpc_client': 'true',
                'identifier': self.identifier
            }
        })
        self.setup_and_run_rpc([InteropAction('large_unary')],
                               config_location = ConfigLocation.FILE,
                               server_config_into_env_var = unused_server_config,
                               client_config_into_env_var = unused_client_config)
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_log_entries_at_least_one()
        logging_results.test_event_type_at_least_one()
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        for metric_name in SUPPORTED_METRICS:
            metrics_results.test_time_series_at_least_one(metric_name)
            metrics_results.test_metric_resource_type(metric_name, self.RESOURCE_TYPE)
            metrics_results.test_metric_resource_labels(metric_name, {
                'project_id': PROJECT
            })
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_results.test_trace_at_least_one()
        trace_results.test_trace_sent_span_exists()
        trace_results.test_trace_recv_span_exists()

    def test_configs_empty_config(self) -> None:
        self.server_config = ObservabilityConfig({})
        self.client_config = ObservabilityConfig({})
        self.setup_and_run_rpc([InteropAction('large_unary')])
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_log_entries_zero()
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        for metric_name in SUPPORTED_METRICS:
            metrics_results.test_time_series_zero(metric_name)
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_results.test_trace_zero_recv_span()
        trace_results.test_trace_zero_sent_span()

    def test_configs_no_config(self) -> None:
        server_proc = self.start_server_in_subprocess()
        server_proc.wait(timeout=5)
        logger.info('Expecting error from server returncode = %d' % server_proc.returncode)
        self.assertGreater(server_proc.returncode, 0)
        self.kill_server_docker_container()

    def test_configs_invalid_config(self) -> None:
        env = os.environ.copy()
        for invalid_config in ['', 'an_invalid_config']:
            self.initialize_config()
            env[CONFIG_ENV_VAR_NAME] = invalid_config
            server_proc = self.start_server_in_subprocess(env = env)
            server_proc.wait(timeout=5)
            logger.info('Expecting error from server returncode = %d' % server_proc.returncode)
            self.assertGreater(server_proc.returncode, 0)
            self.kill_server_docker_container()

    def test_configs_custom_labels(self) -> None:
        SERVER_CUSTOM_LABEL = {'server_app_version': 'v314.15'}
        CLIENT_CUSTOM_LABEL = {'client_app_version': 'v314.15'}
        self.enable_all_config()
        self.set_server_custom_labels({**SERVER_CUSTOM_LABEL,
            'identifier': self.identifier,
        })
        self.set_client_custom_labels({**CLIENT_CUSTOM_LABEL,
            'identifier': self.identifier,
        })
        self.setup_and_run_rpc([InteropAction('large_unary')])
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_custom_labels(LoggerSide.SERVER, SERVER_CUSTOM_LABEL)
        logging_results.test_custom_labels(LoggerSide.CLIENT, CLIENT_CUSTOM_LABEL)
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        for metric_name in SUPPORTED_METRICS:
            if 'server' in metric_name:
                metrics_results.test_metric_labels(metric_name, SERVER_CUSTOM_LABEL)
            else:
                metrics_results.test_metric_labels(metric_name, CLIENT_CUSTOM_LABEL)
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_results.test_span_custom_labels(CloudTraceInterface.RECV_SPAN_PREFIX, SERVER_CUSTOM_LABEL)
        trace_results.test_span_custom_labels(CloudTraceInterface.SENT_SPAN_PREFIX, CLIENT_CUSTOM_LABEL)

    def test_metrics_basic(self) -> None:
        self.enable_server_monitoring()
        self.enable_client_monitoring()
        self.setup_and_run_rpc([InteropAction('large_unary', num_times = 98)])
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        metrics_results.test_metrics_basic(num_rpcs = 98)

    def test_metrics_latency(self) -> None:
        self.enable_server_monitoring()
        self.enable_client_monitoring()
        self.setup_and_run_rpc([InteropAction('large_unary', num_times = 100)])
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        metrics_results.test_metrics_latency()

    def test_metrics_message_bytes(self) -> None:
        self.enable_server_monitoring()
        self.enable_client_monitoring()
        self.setup_and_run_rpc([InteropAction('large_unary')])
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        metrics_results.test_metrics_message_bytes()

    def test_logging_connect_trace(self) -> None:
        self.enable_all_config()
        self.setup_and_run_rpc([InteropAction('large_unary')])
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_ids = []
        for trace in trace_results.results:
            trace_ids.append(trace.trace_id)
        logger.info('Testing whether log entry.trace matches trace_id from traces')
        for entry in logging_results.results:
            trace_id = entry.trace.split('/')[-1]
            self.assertTrue(trace_id in trace_ids)

    def _test_trace_diff_setting_endpoints(self,
                                           server_trace_config: Optional[Dict[str, Any]],
                                           client_trace_config: Optional[Dict[str, Any]]) -> None:
        self.initialize_config()
        self.enable_server_trace(server_trace_config)
        self.enable_client_trace(client_trace_config)
        self.setup_and_run_rpc([InteropAction('large_unary', num_times = 10)])

    def test_trace_diff_setting_endpoints(self) -> None:
        self._test_trace_diff_setting_endpoints(server_trace_config = {
            'sampling_rate': 0.00
        }, client_trace_config = {
            'sampling_rate': 0.00
        })
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_results.test_traces_count(0)

        self._test_trace_diff_setting_endpoints(server_trace_config = {
            'sampling_rate': 0.00
        }, client_trace_config = {
            'sampling_rate': 1.00
        })
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_results.test_traces_count(10)
        if not trace_results.has_recv_span():
            self.fail('Should have some Recv span')
        if not trace_results.has_sent_span():
            self.fail('Should have some Sent span')

        self._test_trace_diff_setting_endpoints(server_trace_config = {
            'sampling_rate': 1.00
        }, client_trace_config = {
            'sampling_rate': 0.00
        })
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_results.test_traces_count(10)
        if trace_results.has_sent_span():
            self.fail('Should not have any Sent span')
        if not trace_results.has_recv_span():
            self.fail('Should have some Recv span')

# Main
if __name__ == "__main__":
    test_runner = TestRunner(parse_args())
    test_runner.run()
