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
import json
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
    ClientActionArgs,
    ConfigLocation,
    ExpectCount,
    JobMode,
    LanguageConstants,
    LoggerSide,
    ObservabilityConfig,
    ObservabilityTestCase,
    ServerStartArgs,
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
ZONE = 'us-central1-c'
OBSERVABILITY_LOG_NAME = 'microservices.googleapis.com%2Fobservability%2Fgrpc'
CONFIG_ENV_VAR_NAME = 'GRPC_GCP_OBSERVABILITY_CONFIG'
CONFIG_FILE_ENV_VAR_NAME = 'GRPC_GCP_OBSERVABILITY_CONFIG_FILE'
IMAGE_TAG = '1.53.0-dev'
SUPPORTED_METRICS = [
    'custom.googleapis.com/opencensus/grpc.io/client/started_rpcs',
    'custom.googleapis.com/opencensus/grpc.io/server/started_rpcs',
    'custom.googleapis.com/opencensus/grpc.io/client/completed_rpcs',
    'custom.googleapis.com/opencensus/grpc.io/server/completed_rpcs',
]
# number of seconds to allow running RPC action command
WAIT_SECS_CLIENT_ACTION = 95
WAIT_SECS_SERVER_START = 20
WAIT_SECS_GKE_DEPLOYMENT = 150
# wait for this many seconds after RPC action to allow exporters to flush
WAIT_SECS_EXPORTER_FLUSH = 65
WAIT_SECS_READY = 20

LANGUAGE_CONSTANTS = {
    SupportedLangEnum.GO: LanguageConstants(
        repo_name = 'grpc-go',
        server_start_cmd = 'interop/observability/server/server',
        server_start_args = '--port {port}',
        client_action_cmd = 'interop/observability/client/client',
        client_action_args = \
        '--server_host={server_host} ' +
        '--server_port={server_port} ' +
        '--export_interval={exporter_interval} ' +
        '--action={action}'
    ),
    SupportedLangEnum.JAVA: LanguageConstants(
        repo_name = 'grpc-java',
        server_start_cmd = \
        'interop-testing/build/install/grpc-interop-testing/bin/observability-test-server',
        server_start_args = '{port}',
        client_action_cmd = \
        'interop-testing/build/install/grpc-interop-testing/bin/observability-test-client',
        client_action_args = '{server_host}:{server_port} {exporter_interval} {action}'
    ),
    SupportedLangEnum.CPP: LanguageConstants(
        repo_name = 'grpc',
        server_start_cmd = 'bazel-bin/test/cpp/interop/interop_server',
        server_start_args = '--port={port}',
        client_action_cmd = 'bazel-bin/test/cpp/interop/interop_client',
        client_action_args = \
        '--server_host={server_host} ' +
        '--server_port={server_port} ' +
        '--test_case=large_unary {action}'
    ),
}

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

class TestRunner:
    args: argparse.Namespace
    job_name: str
    exit_status: int

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.job_name = '%s:%s:%s' % (self.args.server_lang,
                                      self.args.client_lang,
                                      self.args.test_case)
        self.exit_status = 0

    def set_exit_status(self, status: int) -> None:
        self.exit_status = status

    def write_sponge_xml(self) -> None:
        sponge_dir = TestUtil.get_sponge_log_dir(self.args.job_mode, self.job_name)
        with open(os.path.join(sponge_dir, 'sponge_log.xml'), 'w') as f:
            f.write(str(self))

    def __str__(self) -> str:
        timestamp = datetime.now(timezone.utc).isoformat()
        res = '<testsuites>\n'
        res += '  <testsuite errors="0" failures="%d" name="grpc-o11y-%s" ' % (
            self.exit_status, self.job_name)
        res += 'package="grpc-o11y-tests" timestamp="%s">\n' % timestamp
        res += '  </testsuite>\n</testsuites>'
        return res

    def run(self) -> None:
        try:
            impl = TestCaseImpl(self)
            test_case_func = getattr(impl, str(self.args.test_case))
            logger.info('Executing TestCaseImpl.%s()' % str(self.args.test_case))
            test_case_func()
        except Exception:
            self.set_exit_status(1)
            logger.error(traceback.format_exc())
        finally:
            self.write_sponge_xml()
            logger.info("Test case '%s' %s." % (self.args.test_case,
                                             'failed' if self.exit_status else 'passed'))
            sys.exit(self.exit_status)

class GKETestEnv:
    args: argparse.Namespace
    k8s_core_v1: kubernetes_client.CoreV1Api
    k8s_client: kubernetes_client.ApiClient
    server_pod_stream: kubernetes_stream
    server_pod_name: str
    server_pod_ip: str
    server_pid: str
    client_pod_name: str

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.SERVER_NAMESPACE = 'grpc-server-ns-%s' % args.gke_resource_identifier
        self.CLIENT_NAMESPACE = 'grpc-client-ns-%s' % args.gke_resource_identifier
        self.SERVER_CONTAINER_NAME = 'grpc-server-ctnr-%s' % args.gke_resource_identifier
        self.CLIENT_CONTAINER_NAME = 'grpc-client-ctnr-%s' % args.gke_resource_identifier
        self.k8s_core_v1 = None
        self.k8s_client = None
        self.server_pod_stream = None
        self.server_pod_name = ''
        self.server_pod_ip = ''
        self.server_pid = ''
        self.client_pod_name = ''

    def get_image_name(self, lang: SupportedLang, job_mode: JobMode) -> str:
        return 'gcr.io/%s/grpc-observability/testing/%s-%s:%s' % (PROJECT, job_mode, lang, IMAGE_TAG)

    def set_config_cmd(self, config: ObservabilityConfig) -> str:
        return "export %s='%s'" % (CONFIG_ENV_VAR_NAME, config.toJson())

    def load_kubernetes_context(self) -> None:
        contexts, _ = kubernetes_config.list_kube_config_contexts()
        picked_context = ''
        for context in contexts:
            if PROJECT in context['context']['cluster'] and CLUSTER_NAME in context['context']['cluster']:
                if picked_context:
                    raise Exception('Found multiple kubernetes config on the same project.')
                picked_context = context['name']
        logger.info('Using kubernetes context: %s' % picked_context)
        kubernetes_config.load_kube_config(context=picked_context)
        self.k8s_core_v1 = kubernetes_client.CoreV1Api()
        self.k8s_client = kubernetes_client.ApiClient()

    def deploy_gke_resources(self) -> None:
        # Do string replacements on deployment yaml file
        replacements = {
            '${PROJECT}': PROJECT,
            '${PROJNUM}': PROJECT_NUM,
            '${SERVER_IMAGE}': self.get_image_name(self.args.server_lang, self.args.job_mode),
            '${CLIENT_IMAGE}': self.get_image_name(self.args.client_lang, self.args.job_mode),
            '${JOB_MODE}': self.args.gke_resource_identifier,
        }
        yaml_file_data = ''
        with open(os.path.join(os.path.dirname(__file__), 'gke-deployment.yaml'), 'r') as f:
            yaml_file_data = f.read()
        for orig, replacement in replacements.items():
            yaml_file_data = yaml_file_data.replace(orig, replacement)
        logger.info('Applying deployment from yaml...')
        logger.info(yaml_file_data)
        tmp_file_path = '/tmp/%s:%s:%s.yaml' % (self.args.server_lang,
                                                self.args.client_lang,
                                                self.args.gke_resource_identifier)
        with open(tmp_file_path, 'w') as f:
            f.write(yaml_file_data)
        # Deploy to GKE cluster
        kubernetes_utils.create_from_yaml(self.k8s_client, tmp_file_path, verbose=True)
        logger.info('Waiting for pods to be ready...')
        timeout_target = int(time.time()) + WAIT_SECS_GKE_DEPLOYMENT
        while True:
            try:
                if int(time.time()) > timeout_target:
                    break
                time.sleep(10)
                self.get_active_pod_data()
                return
            except Exception:
                logger.error(traceback.format_exc())
        raise Exception('GKE resources still not ready after %d seconds' % WAIT_SECS_GKE_DEPLOYMENT)

    def clean_up_gke_resources(self) -> None:
        f = os.popen(os.path.join(os.path.dirname(__file__), 'cleanup.sh ' +
                                  self.args.gke_resource_identifier))
        output = f.read()
        logger.info(output)

    def get_active_pod_data(self) -> None:
        ret = self.k8s_core_v1.list_namespaced_pod(self.SERVER_NAMESPACE)
        for i in ret.items:
            logger.debug('%s\t%s\t%s' % (i.status.pod_ip, i.metadata.name, i.status.phase))
            if self.server_pod_name and i.metadata.name != self.server_pod_name:
                raise Exception('Somehow found more than 1 pod in the server namespace.')
            if i.status.phase != 'Running':
                raise Exception('%s is not ready yet.' % i.metadata.name)
            self.server_pod_name = i.metadata.name
            self.server_pod_ip = i.status.pod_ip
        ret = self.k8s_core_v1.list_namespaced_pod(self.CLIENT_NAMESPACE)
        for i in ret.items:
            logger.debug('%s\t%s\t%s' % (i.status.pod_ip, i.metadata.name, i.status.phase))
            if self.client_pod_name and i.metadata.name != self.client_pod_name:
                raise Exception('Somehow found more than 1 pod in the client namespace.')
            if i.status.phase != 'Running':
                raise Exception('%s is not ready yet.' % i.metadata.name)
            self.client_pod_name = i.metadata.name
        if not self.server_pod_name:
            raise Exception('No server pod found in %s.' % self.SERVER_NAMESPACE)
        if not self.client_pod_name:
            raise Exception('No client pod found in %s.' % self.CLIENT_NAMESPACE)

    def _test_pid(self, s):
        if m := re.match('PID=(\d+)', s):
            return m.group(1)
        return False

    def exec_commands_in_pod(self,
                             pod_name: str,
                             namespace: str,
                             timeout_sec: int,
                             commands: List[str]) -> Tuple[kubernetes_stream, str]:
        stream_resp = kubernetes_stream(self.k8s_core_v1.connect_get_namespaced_pod_exec,
                                        pod_name, namespace, command='/bin/bash',
                                        stderr=True, stdin=True,
                                        stdout=True, tty=False,
                                        _preload_content=False)
        target_sec = int(time.time()) + timeout_sec
        pid = ''
        while stream_resp.is_open():
            stream_resp.update(timeout=500) # in ms
            if stream_resp.peek_stdout():
                stdout = stream_resp.read_stdout().strip()
                if not pid:
                    pid =  self._test_pid(stdout)
                logger.info(stdout)
            if stream_resp.peek_stderr():
                stderr = stream_resp.read_stderr().strip()
                if not pid:
                    pid =  self._test_pid(stderr)
                logger.error(stderr)
            if commands:
                c = commands.pop(0)
                logger.info('%s:$ %s' % (pod_name, c))
                stream_resp.write_stdin(c + '\n')
            if int(time.time()) > target_sec:
                break
        return stream_resp, pid

    def start_testservice_server(self,
                                 server_config: ObservabilityConfig,
                                 timeout_secs: int,
                                 server_start_cmd: str) -> None:
        commands = [
            self.set_config_cmd(server_config),
            server_start_cmd,
            'echo "PID=$!"'
        ]
        self.server_pod_stream, self.server_pid = self.exec_commands_in_pod(
            self.server_pod_name, self.SERVER_NAMESPACE, timeout_secs, commands)

    def kill_testservice_server(self) -> None:
        logger.info('Killing process %s' % self.server_pid)
        self.server_pod_stream.write_stdin('kill -9 %s\n' % self.server_pid)
        self.server_pod_stream.close()

    def run_client_commands(self,
                            client_config: ObservabilityConfig,
                            timeout_secs: int,
                            commands: List[str]) -> None:
        client_pod_stream, _ = self.exec_commands_in_pod(
            self.client_pod_name, self.CLIENT_NAMESPACE, timeout_secs, [
            self.set_config_cmd(client_config)
        ] + commands)
        client_pod_stream.close()

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
                         (event_type, str(logger_side), method_name, num))
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
                logger.debug('%s %s: %d %s' % (t.payload['logger'], t.payload['type'],
                                               len(t.payload['payload']), t.payload['payload']))
                self.assertEqual(len(t.payload['payload']), expect_num_entries)

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
            'start_time': {'seconds': test_impl.test_run_metadata.script_start_seconds,
                           'nanos': test_impl.test_run_metadata.nanos},
        })
        metrics_results: Dict[str, List[ListTimeSeriesResponse]] = {}
        for metric_name in SUPPORTED_METRICS:
            method_label = 'grpc_client_method' if 'client' in metric_name else 'grpc_server_method'
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
        if self.count_total(metric_name) == 0:
            return
        for result in self.results[metric_name]:
            self.assertEqual(result.resource.type, resource_type)

    def test_metric_resource_labels(self, metric_name: str, resource_labels: Dict[str, str]) -> None:
        if self.count_total(metric_name) == 0:
            return
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
            start_time=Timestamp(seconds=test_impl.test_run_metadata.script_start_seconds),
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

    def test_traces_count(self, lower_bound: int, upper_bound: int) -> None:
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
        self.identifier = self.generate_identifier()
        self.test_run_metadata = TestRunMetadata()
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
        sponge_log_file = os.path.join(TestUtil.get_sponge_log_dir(
            self.args.job_mode, self.test_runner.job_name), 'sponge_log.log')
        self.sponge_log_out = open(sponge_log_file, 'a')

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

    def generate_identifier(self) -> str:
        identifier = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        identifier += datetime.now(timezone.utc).strftime('%y%m%d%H%M%S')
        logger.info('Generated identifier: %s' % identifier)
        return identifier

    def get_server_start_cmd(self, server_lang: SupportedLang) -> str:
        return LANGUAGE_CONSTANTS[server_lang.toEnum()].server_start_cmd

    def get_server_start_args(self,
                              server_lang: SupportedLang,
                              server_args: ServerStartArgs) -> str:
        return LANGUAGE_CONSTANTS[server_lang.toEnum()].get_server_start_args_replaced(server_args)

    def get_client_action_cmd(self, client_lang: SupportedLang) -> str:
        return LANGUAGE_CONSTANTS[client_lang.toEnum()].client_action_cmd

    def get_client_action_args(self,
                               client_lang: SupportedLang,
                               client_args: ClientActionArgs) -> str:
        return LANGUAGE_CONSTANTS[client_lang.toEnum()].get_client_action_args_replaced(client_args)

    def get_repo_path(self, lang: SupportedLangEnum) -> str:
        repos_base_dir = os.environ.get('REPOS_BASE_DIR')
        if not repos_base_dir:
            raise ValueError('Env var REPOS_BASE_DIR is not defined')
        return os.path.join(repos_base_dir, LANGUAGE_CONSTANTS[lang].repo_name)

    def wait_before_querying_o11y_data(self) -> None:
        logger.info('Wait %d seconds before querying cloud...' % WAIT_SECS_READY)
        time.sleep(WAIT_SECS_READY)

    def get_env_with_config(self,
                            config: ObservabilityConfig,
                            config_file_name: str = '') -> Dict[str, Any]:
        env = os.environ.copy()
        if config_file_name:
            config_file_path = '/tmp/%s' % config_file_name
            with open(config_file_path, 'w') as f:
                logger.debug('Writing config to file %s: %s' % (config_file_path, config.toJson()))
                f.write(config.toJson())
            env[CONFIG_FILE_ENV_VAR_NAME] = config_file_path
        else:
            env[CONFIG_ENV_VAR_NAME] = config.toJson()
        return env

    def start_server_in_subprocess(self, env: Optional[Dict[str, Any]] = None) -> subprocess.Popen:
        server_start_cmd = os.path.join(self.get_repo_path(self.args.server_lang.toEnum()),
                                        self.get_server_start_cmd(self.args.server_lang))
        server_args = self.get_server_start_args(self.args.server_lang,
                                                 ServerStartArgs(port = self.args.port))
        logger.info('Starting server at port %s...' % self.args.port)
        server_proc = subprocess.Popen([server_start_cmd] + server_args.split(),
                                       stdout=self.sponge_log_out,
                                       stderr=self.sponge_log_out,
                                       env=env)
        return server_proc

    def start_client_in_subprocess(self,
                                   action: str,
                                   env: Optional[Dict[str, Any]] = None) -> subprocess.Popen:
        client_action_cmd = os.path.join(self.get_repo_path(self.args.client_lang.toEnum()),
                                         self.get_client_action_cmd(self.args.client_lang))
        client_args = self.get_client_action_args(
            self.args.client_lang,
            ClientActionArgs(server_host = 'localhost',
                             server_port = self.args.port,
                             action = action,
                             exporter_interval = WAIT_SECS_EXPORTER_FLUSH))
        logger.info('Running %s' % action)
        client_proc = subprocess.Popen([client_action_cmd] + client_args.split(),
                                       stdout=self.sponge_log_out,
                                       stderr=self.sponge_log_out,
                                       env=env)
        return client_proc

    def setup_and_run_rpc_gke(self, action: str) -> None:
        gke_env = GKETestEnv(self.args)
        gke_env.load_kubernetes_context()
        try:
            gke_env.deploy_gke_resources()
            server_start_cmd = './%s %s &' % (
                self.get_server_start_cmd(self.args.server_lang),
                self.get_server_start_args(self.args.server_lang,
                                           ServerStartArgs(port = self.args.port))
            )
            gke_env.start_testservice_server(self.server_config, WAIT_SECS_SERVER_START,
                                             server_start_cmd)
            client_action_cmd = './%s %s' % (
                self.get_client_action_cmd(self.args.client_lang),
                self.get_client_action_args(
                    self.args.client_lang,
                    ClientActionArgs(server_host = gke_env.server_pod_ip,
                                     server_port = self.args.port,
                                     action = action,
                                     exporter_interval = WAIT_SECS_EXPORTER_FLUSH)))
            gke_env.run_client_commands(self.client_config, WAIT_SECS_CLIENT_ACTION, [
                client_action_cmd,
            ])
            gke_env.kill_testservice_server()
            self.wait_before_querying_o11y_data()
        except Exception:
            self.test_runner.set_exit_status(1)
            logger.error(traceback.format_exc())
        finally:
            gke_env.clean_up_gke_resources()
            self.sponge_log_out.close()

    def setup_and_run_rpc_vm(self,
                             action: str,
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
        else:
            server_env = self.get_env_with_config(self.server_config)
            client_env = self.get_env_with_config(self.client_config)
        if server_config_into_env_var:
            server_env[CONFIG_ENV_VAR_NAME] = server_config_into_env_var.toJson()
        if client_config_into_env_var:
            client_env[CONFIG_ENV_VAR_NAME] = client_config_into_env_var.toJson()
        server_proc = self.start_server_in_subprocess(env = server_env)
        time.sleep(WAIT_SECS_SERVER_START)
        try:
            client_proc = self.start_client_in_subprocess(action, env = client_env)
            client_proc.wait(timeout=WAIT_SECS_CLIENT_ACTION)
            self.wait_before_querying_o11y_data()
        except Exception:
            self.test_runner.set_exit_status(1)
            logger.error(traceback.format_exc())
        finally:
            logger.info('Killing server...')
            os.kill(server_proc.pid, signal.SIGTERM)
            server_proc.wait(timeout=5)
            self.sponge_log_out.close()

    def test_logging_basic(self) -> None:
        self.enable_server_logging()
        self.enable_client_logging()
        self.setup_and_run_rpc_vm('doUnaryCall')
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_log_entries_at_least_one()
        logging_results.test_event_type_at_least_one()

    def test_monitoring_basic(self) -> None:
        self.enable_server_monitoring()
        self.enable_client_monitoring()
        self.setup_and_run_rpc_vm('doUnaryCall')
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        for metric_name in SUPPORTED_METRICS:
            metrics_results.test_time_series_at_least_one(metric_name)
            metrics_results.test_metric_resource_type(metric_name, 'gce_instance')
            metrics_results.test_metric_resource_labels(metric_name, {
                'project_id': PROJECT,
            })

    def test_trace_basic(self) -> None:
        self.enable_server_trace()
        self.enable_client_trace()
        self.setup_and_run_rpc_vm('doUnaryCall')
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_results.test_trace_at_least_one()
        trace_results.test_trace_sent_span_exists()
        trace_results.test_trace_recv_span_exists()

    def test_resource_labels_gke(self) -> None:
        self.enable_all_config()
        self.setup_and_run_rpc_gke('doUnaryCall')
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_log_entries_at_least_one()
        logging_results.test_event_type_at_least_one()
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        for metric_name in SUPPORTED_METRICS:
            metrics_results.test_time_series_at_least_one(metric_name)
            metrics_results.test_metric_resource_type(metric_name, 'k8s_container')
            metrics_results.test_metric_resource_labels(metric_name, {
                'cluster_name': CLUSTER_NAME,
                'location': ZONE,
                'project_id': PROJECT
            })
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_results.test_trace_at_least_one()
        trace_results.test_trace_sent_span_exists()
        trace_results.test_trace_recv_span_exists()

    def test_configs_disable_logging(self) -> None:
        self.setup_and_run_rpc_vm('doUnaryCall')
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_log_entries_zero()

    def test_configs_disable_monitoring(self) -> None:
        self.setup_and_run_rpc_vm('doUnaryCall')
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        for metric_name in SUPPORTED_METRICS:
            metrics_results.test_time_series_zero(metric_name)

    def test_configs_disable_trace(self) -> None:
        self.setup_and_run_rpc_vm('doUnaryCall')
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        trace_results.test_trace_zero_recv_span()
        trace_results.test_trace_zero_sent_span()

    def test_streaming(self) -> None:
        self.enable_all_config()
        self.setup_and_run_rpc_vm('doFullDuplexCall')
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_log_entries_at_least_one()
        logging_results.test_event_type_at_least_one()
        logging_results.test_log_entry_count(LoggerSide.SERVER, 'CLIENT_MESSAGE', 'FullDuplexCall', 5)
        logging_results.test_log_entry_count(LoggerSide.SERVER, 'SERVER_MESSAGE', 'FullDuplexCall', 5)
        logging_results.test_log_entry_count(LoggerSide.CLIENT, 'CLIENT_MESSAGE', 'FullDuplexCall', 5)
        logging_results.test_log_entry_count(LoggerSide.CLIENT, 'SERVER_MESSAGE', 'FullDuplexCall', 5)
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        for metric_name in SUPPORTED_METRICS:
            metrics_results.test_time_series_at_least_one(metric_name)
            metrics_results.test_metric_resource_type(metric_name, 'gce_instance')
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
        self.setup_and_run_rpc_vm('doUnaryCall,doFullDuplexCall')
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
        self.setup_and_run_rpc_vm('doUnaryCall,doFullDuplexCall')
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
        self.setup_and_run_rpc_vm('doUnaryCall,doFullDuplexCall')
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
            'max_metadata_bytes': 29,
        }])
        self.enable_client_logging([{
            'methods': ['*'],
            'max_metadata_bytes': 29,
        }])
        self.setup_and_run_rpc_vm('doUnaryCall')
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
        self.setup_and_run_rpc_vm('doUnaryCall')
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
        self.setup_and_run_rpc_vm(','.join(['doUnaryCall' for i in range(0, 20)]))
        trace_results = CloudTraceInterface.query_traces_from_cloud(self)
        # With 50%, we should get 5-15 traces with 98.8% probability
        trace_results.test_traces_count(5, 15)

    def test_configs_env_var(self) -> None:
        self.enable_all_config()
        self.setup_and_run_rpc_vm('doUnaryCall',
                                  config_location = ConfigLocation.ENV_VAR)
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_log_entries_at_least_one()
        logging_results.test_event_type_at_least_one()
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        for metric_name in SUPPORTED_METRICS:
            metrics_results.test_time_series_at_least_one(metric_name)
            metrics_results.test_metric_resource_type(metric_name, 'gce_instance')
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
        self.setup_and_run_rpc_vm('doUnaryCall',
                                  config_location = ConfigLocation.FILE,
                                  server_config_into_env_var = unused_server_config,
                                  client_config_into_env_var = unused_client_config)
        logging_results = CloudLoggingInterface.query_logging_entries_from_cloud(self)
        logging_results.test_log_entries_at_least_one()
        logging_results.test_event_type_at_least_one()
        metrics_results = CloudMonitoringInterface.query_metrics_from_cloud(self)
        for metric_name in SUPPORTED_METRICS:
            metrics_results.test_time_series_at_least_one(metric_name)
            metrics_results.test_metric_resource_type(metric_name, 'gce_instance')
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
        self.setup_and_run_rpc_vm('doUnaryCall')
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
        self.sponge_log_out.close()

    def test_configs_invalid_config(self) -> None:
        env = os.environ.copy()
        env[CONFIG_ENV_VAR_NAME] = 'an_invalid_config'
        server_proc = self.start_server_in_subprocess(env = env)
        server_proc.wait(timeout=5)
        logger.info('Expecting error from server returncode = %d' % server_proc.returncode)
        self.assertGreater(server_proc.returncode, 0)
        self.sponge_log_out.close()

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
        self.setup_and_run_rpc_vm('doUnaryCall')
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

# Main
test_runner = TestRunner(parse_args())
test_runner.run()
