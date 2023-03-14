#!/usr/bin/env python3
# Copyright 2023 gRPC authors.
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
"""Run gRPC Observability interop test locally"""

import argparse
import docker # type: ignore
import logging
import os
import subprocess
import sys
from test_utils import (
    ObservabilityTestCase
)

SPONGE_LOGS_DIR = '/tmp/observability_test_log' # a directory in your local environment for logs
DOCKER_IMAGE_NAME = 'gcr.io/microsvcs-testing/grpc-observability/testing/integration-%s:latest'

argp = argparse.ArgumentParser(description='Run Observability integration tests in local env')
argp.add_argument('--server_lang', required=True, type=str, choices=['java', 'go', 'cpp'],
                  help='Server language')
argp.add_argument('--client_lang', required=True, type=str, choices=['java', 'go', 'cpp'],
                  help='Client language')
argp.add_argument('--test_case', required=True, type=str,
                  help='Test case to run: see test_utils.py')
argp.add_argument('--docker_image_go', default=DOCKER_IMAGE_NAME % 'go', type=str,
                  help='docker image tag for Go interop client/server')
argp.add_argument('--docker_image_java', default=DOCKER_IMAGE_NAME % 'java', type=str,
                  help='docker image tag for Java interop client/server')
argp.add_argument('--docker_image_cpp', default=DOCKER_IMAGE_NAME % 'cpp', type=str,
                  help='docker image tag for C++ interop client/server')
args = argp.parse_args()

docker_client = docker.from_env()

logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
formatter = logging.Formatter(fmt='%(asctime)s: %(levelname)-8s %(message)s')
console_handler.setFormatter(formatter)
logger.handlers = []
logger.addHandler(console_handler)
logger.setLevel(logging.DEBUG)

def prepare_docker_image(lang):
    args_dict = vars(args)
    image_name = args_dict['docker_image_%s' % lang]
    images = docker_client.images.list(name=image_name)
    if len(images) == 0:
        logger.warning("Docker image '%s' does not exist locally. Trying to docker pull ..." % image_name)
        try:
            if not docker_client.images.pull(repository=image_name):
                raise Exception('No image found')
        except:
            logger.error("Still could not find docker image '%s'. Exiting...'" % image_name)
            sys.exit(1)
    logger.info("Using local docker image '%s'" % image_name)
    os.environ['OBSERVABILITY_TEST_IMAGE_%s' % lang.upper()] = image_name

def main():
    os.makedirs(SPONGE_LOGS_DIR, exist_ok=True)
    prepare_docker_image(args.server_lang)
    prepare_docker_image(args.client_lang)
    if args.test_case == 'all':
        for test_case in ObservabilityTestCase:
            run_test_case(test_case)
    else:
        run_test_case(args.test_case)

def run_test_case(test_case):
    os.environ['RESOURCE_TYPE_ASSERTION_OVERRIDE'] = 'global'
    os.environ['CUSTOM_DOCKER_RUN_AUTH'] = \
        '-v %s/.config/gcloud:/root/.config/gcloud' % os.environ.get('HOME')
    os.environ['KOKORO_ARTIFACTS_DIR'] = SPONGE_LOGS_DIR
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), 'run_o11y_tests.py'),
         '--server_lang', args.server_lang,
         '--client_lang', args.client_lang,
         '--job_mode', 'integration',
         '--test_case', test_case,
         '--port', '14286'])
    proc.wait()

# Main
if __name__ == "__main__":
    main()
