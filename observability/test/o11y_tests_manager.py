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
"""gRPC Observability Integration Tests Manager"""

import argparse
import logging
import os
import random
import string
import subprocess
import sys
from test_utils import (
    JobMode,
    ObservabilityTestCase,
    SupportedLang,
    SupportedLangEnum,
    TestUtil,
)
import threading
import traceback
from typing import Dict, List

INTEROP_COMBINATIONS = [
    { 'server_lang': SupportedLangEnum.JAVA, 'client_lang': SupportedLangEnum.GO   },
    { 'server_lang': SupportedLangEnum.GO,   'client_lang': SupportedLangEnum.JAVA },
]

INTEROP_TEST_CASES = [
    ObservabilityTestCase.TEST_TRACE_BASIC,
    ObservabilityTestCase.TEST_STREAMING,
]

NUM_INTEROP_QUEUES = 2
NUM_LANG_QUEUES = 10
TIMEOUT_SECS_BACKGROUND_PROCESS = 1800 # 30 minutes

logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
formatter = logging.Formatter(fmt='%(asctime)s: %(levelname)-8s %(message)s')
console_handler.setFormatter(formatter)
logger.handlers = []
logger.addHandler(console_handler)
logger.setLevel(logging.DEBUG)

def parse_args() -> argparse.Namespace:
    argp = argparse.ArgumentParser(description='Observability integration tests manager')
    argp.add_argument('--job_mode', required=True, type=lambda s:JobMode(s),
                      help='Job mode')
    argp.add_argument('--language', required=True, type=lambda s:SupportedLang(s),
                      help="Run tests for a single language, or '%s'" % SupportedLangEnum.INTEROP)
    args = argp.parse_args()
    logger.debug('Parsed args: ' + str({k: str(v) for k, v in vars(args).items()}))
    return args

class TestJob:
    server_lang: SupportedLang
    client_lang: SupportedLang
    test_case: ObservabilityTestCase
    job_name: str
    port: int

    def __init__(self,
                 server_lang: SupportedLang,
                 client_lang: SupportedLang,
                 test_case: ObservabilityTestCase,
                 job_name: str,
                 port: int) -> None:
        self.server_lang = server_lang
        self.client_lang = client_lang
        self.test_case = test_case
        self.job_name = job_name
        self.port = port

class _BaseKey:
    key: str

    def __init__(self, key: str) -> None:
        self.key = key

    def __hash__(self) -> int:
        return hash(str(self))

    def __eq__(self, other) -> bool:
        return self.key == other.key

    def __str__(self) -> str:
        return self.key

class QueueKey(_BaseKey):
    pass

class InteropEntryKey(_BaseKey):
    pass

class JobQueue:
    jobs: List[TestJob]
    server_lang: SupportedLang
    client_lang: SupportedLang
    queue_num: int
    gke_resource_identifier: str

    def __init__(self,
                 server_lang: SupportedLang,
                 client_lang: SupportedLang,
                 queue_num: int,
                 gke_resource_identifier: str) -> None:
        self.jobs = []
        self.server_lang = server_lang
        self.client_lang = client_lang
        self.queue_num = queue_num
        self.gke_resource_identifier = gke_resource_identifier

    def add_job(self, job: TestJob) -> None:
        self.jobs.append(job)

class TestRunner:
    args: argparse.Namespace
    exit_status: int

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.exit_status = 0

    def set_exit_status(self, status: int) -> None:
        self.exit_status = status

    def run_tests(self) -> None:
        test_manager = TestManager(self)
        try:
            test_manager.run_all_test_cases()
        except Exception:
            self.set_exit_status(1)
            logger.error(traceback.format_exc())
        finally:
            logger.info("Observability test job for '%s' %s." % (
                self.args.language, 'failed' if self.exit_status else 'passed'))
            sys.exit(self.exit_status)

class TestManager:
    args: argparse.Namespace
    test_runner: TestRunner
    job_queues: Dict[QueueKey, JobQueue]
    curr_port_num: int
    curr_interop_shard_nums: Dict[InteropEntryKey, int]
    curr_lang_shard_nums: Dict[SupportedLang, int]

    def __init__(self, test_runner: TestRunner) -> None:
        self.args = test_runner.args
        self.test_runner = test_runner
        self.job_queues = {}
        self.curr_port_num = 14285
        self.curr_interop_shard_nums = {}
        self.curr_lang_shard_nums = {}
        if self.args.language.toEnum() == SupportedLangEnum.INTEROP:
            self.initialize_interop()
            self.add_interop_jobs()
        else:
            self.initialize_single_lang(self.args.language)
            self.add_lang_jobs(self.args.language)

    def initialize_single_lang(self, lang: SupportedLang) -> None:
        self.curr_lang_shard_nums[lang] = 0
        logger.info('Initializing %d job queues for %s' % (NUM_LANG_QUEUES, lang))
        for i in range(0, NUM_LANG_QUEUES):
            queue_key = QueueKey('%s:%d' % (lang, i))
            self.job_queues[queue_key] = JobQueue(
                server_lang = lang,
                client_lang = lang,
                queue_num = i,
                gke_resource_identifier = self.generate_gke_resource_identifier(),
            )

    def initialize_interop(self) -> None:
        logger.info('Initializing %d job queues for each interop combinations' % NUM_INTEROP_QUEUES)
        for entry in INTEROP_COMBINATIONS:
            entry_key = InteropEntryKey('%s:%s' % (entry['server_lang'], entry['client_lang']))
            self.curr_interop_shard_nums[entry_key] = 0
            for i in range(0, NUM_INTEROP_QUEUES):
                queue_key = QueueKey('%s:%d' % (entry_key, i))
                self.job_queues[queue_key] = JobQueue(
                    server_lang = SupportedLang(entry['server_lang']),
                    client_lang = SupportedLang(entry['client_lang']),
                    queue_num = i,
                    gke_resource_identifier = self.generate_gke_resource_identifier(),
                )

    def generate_gke_resource_identifier(self) -> str:
        return '%s-%s' % (self.args.job_mode,
                          ''.join(random.choices(string.ascii_lowercase + string.digits, k=6)))

    def add_job_to_job_queue(self,
                             queue_key: QueueKey,
                             server_lang: SupportedLang,
                             client_lang: SupportedLang,
                             test_case: ObservabilityTestCase) -> None:
        self.job_queues[queue_key].add_job(TestJob(
            server_lang = server_lang,
            client_lang = client_lang,
            test_case = test_case,
            job_name = '%s:%s:%s' % (server_lang, client_lang, test_case),
            port = self.curr_port_num,
        ))
        self.curr_port_num += 1

    def get_next_interop_shard_num(self, entry_key: InteropEntryKey) -> int:
        num = self.curr_interop_shard_nums[entry_key]
        self.curr_interop_shard_nums[entry_key] = (num + 1) % NUM_INTEROP_QUEUES
        return num

    def get_next_lang_shard_num(self, lang: SupportedLang) -> int:
        num = self.curr_lang_shard_nums[lang]
        self.curr_lang_shard_nums[lang] = (num + 1) % NUM_LANG_QUEUES
        return num

    def add_interop_jobs(self) -> None:
        for entry in INTEROP_COMBINATIONS:
            entry_key = InteropEntryKey('%s:%s' % (entry['server_lang'], entry['client_lang']))
            for test_case in INTEROP_TEST_CASES:
                queue_key = QueueKey('%s:%d' % (entry_key, self.get_next_interop_shard_num(entry_key)))
                self.add_job_to_job_queue(queue_key,
                                          SupportedLang(entry['server_lang']),
                                          SupportedLang(entry['client_lang']),
                                          test_case)

    def add_lang_jobs(self, lang: SupportedLang) -> None:
        for test_case in ObservabilityTestCase:
            queue_key = QueueKey('%s:%d' % (lang, self.get_next_lang_shard_num(lang)))
            self.add_job_to_job_queue(queue_key, lang, lang, test_case)

    def start_process_in_background(self,
                                    job: TestJob,
                                    queue_key: QueueKey,
                                    extra_args: List[str] = []) -> subprocess.Popen:
        sponge_log_dir = TestUtil.get_sponge_log_dir(self.args.job_mode, job.job_name)
        # Note: the corresponding sponge_log.xml is being written in run_o11y_tests.py itself
        with open(os.path.join(sponge_log_dir, 'sponge_log.log'), 'a') as out:
            logger.info('Starting %s, in queue %s' % (job.job_name, queue_key))
            env = os.environ.copy()
            env['GRPC_VERBOSITY'] = 'DEBUG'
            return subprocess.Popen(
                [os.path.join(os.path.dirname(__file__), 'run_o11y_tests.py'),
                 '--server_lang', str(job.server_lang),
                 '--client_lang', str(job.client_lang),
                 '--job_mode', str(self.args.job_mode),
                 '--test_case', job.test_case] + extra_args,
                stdout=out,
                stderr=out,
                env=env)

    def start_all_job_queues(self) -> Dict[QueueKey, threading.Thread]:
        threads: Dict[QueueKey, threading.Thread] = {}
        max_job_queue_size = 0
        for queue_key, job_queue in self.job_queues.items():
            thd = threading.Thread(target=self.run_job_queue, args=(queue_key,))
            threads[queue_key] = thd
            thd.start()
            if len(job_queue.jobs) > max_job_queue_size:
                max_job_queue_size = len(job_queue.jobs)
        logger.info('Max job queue size: %d' % max_job_queue_size)
        return threads

    def run_job_queue(self, queue_key: QueueKey) -> None:
        job_queue = self.job_queues[queue_key]
        for job in job_queue.jobs:
            try:
                proc = self.start_process_in_background(
                    job,
                    queue_key,
                    extra_args = [
                        '--gke_resource_identifier', job_queue.gke_resource_identifier,
                        '--port', str(job.port)
                    ]
                )
                logger.info('Waiting for %s to finish' % job.job_name)
                proc.wait(timeout=TIMEOUT_SECS_BACKGROUND_PROCESS)
                if proc.returncode != 0:
                    self.test_runner.set_exit_status(1)
                    logger.error('Failed: %s' % job.job_name)
                else:
                    logger.info('Passed: %s' % job.job_name)
            except Exception:
                self.test_runner.set_exit_status(1)
                logger.error('Failed: %s' % job.job_name)
                logger.error(traceback.format_exc())

    def run_all_test_cases(self) -> None:
        threads = self.start_all_job_queues()
        for queue_key, thd in threads.items():
            thd.join()
            logger.info('Queue %s is done' % queue_key)

# Main
test_runner = TestRunner(parse_args())
test_runner.run_tests()
