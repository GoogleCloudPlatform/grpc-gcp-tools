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
"""gRPC Observability integration tests utils"""

from enum import Enum
import json
import os
import time
from typing import Any, Dict, Union

class ObservabilityTestCase(str, Enum):
    TEST_LOGGING_BASIC = 'test_logging_basic'
    TEST_MONITORING_BASIC = 'test_monitoring_basic'
    TEST_TRACE_BASIC = 'test_trace_basic'
    TEST_CONFIGS_DISABLE_LOGGING = 'test_configs_disable_logging'
    TEST_CONFIGS_DISABLE_MONITORING = 'test_configs_disable_monitoring'
    TEST_CONFIGS_DISABLE_TRACE = 'test_configs_disable_trace'
    TEST_STREAMING = 'test_streaming'
    TEST_CONFIGS_LOGGING_SERVICE_FILTER = 'test_configs_logging_service_filter'
    TEST_CONFIGS_LOGGING_METHOD_FILTER = 'test_configs_logging_method_filter'
    TEST_CONFIGS_LOGGING_EXCLUDE_FILTER = 'test_configs_logging_exclude_filter'
    TEST_CONFIGS_LOGGING_METADATA_LIMIT = 'test_configs_logging_metadata_limit'
    TEST_CONFIGS_LOGGING_PAYLOAD_LIMIT = 'test_configs_logging_payload_limit'
    TEST_CONFIGS_TRACE_SAMPLING_RATE = 'test_configs_trace_sampling_rate'
    TEST_CONFIGS_ENV_VAR = 'test_configs_env_var'
    TEST_CONFIGS_FILE_OVER_ENV_VAR = 'test_configs_file_over_env_var'
    TEST_CONFIGS_EMPTY_CONFIG = 'test_configs_empty_config'
    TEST_CONFIGS_NO_CONFIG = 'test_configs_no_config'
    TEST_CONFIGS_INVALID_CONFIG = 'test_configs_invalid_config'
    TEST_CONFIGS_CUSTOM_LABELS = 'test_configs_custom_labels'

    def __str__(self) -> str:
        return self.value

class SupportedLangEnum(str, Enum):
    JAVA = 'java'
    GO = 'go'
    CPP = 'cpp'
    INTEROP = 'interop'

    def __str__(self) -> str:
        return self.value

class SupportedLang():
    lang: SupportedLangEnum

    def __init__(self, lang: Union[str, SupportedLangEnum]) -> None:
        self.lang = SupportedLangEnum(lang) if isinstance(lang, str) else lang

    def __str__(self) -> str:
        return str(self.lang)

    def toEnum(self) -> SupportedLangEnum:
        return self.lang

class JobMode(str, Enum):
    INTEGRATION_DEV = 'integration-dev'
    INTEGRATION = 'integration'

    def __str__(self) -> str:
        return self.value

class ObservabilityConfig:
    config: Dict[str, Any]

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config

    def setdefault(self, key: str, value: Any) -> None:
        self.config.setdefault(key, value)

    def set(self, key: str, value: Any) -> None:
        self.config[key] = value

    def toJson(self) -> str:
        return json.dumps(self.config)

class TestRunMetadata:
    test_case_start_time: float
    test_case_start_seconds: int
    nanos: int

    def __init__(self) -> None:
        self.test_case_start_time = time.time()
        self.test_case_start_seconds = int(self.test_case_start_time)
        self.nanos = int((self.test_case_start_time - self.test_case_start_seconds) * 10**9)

class LoggerSide(str, Enum):
    SERVER = 1
    CLIENT = 2

    def __str__(self) -> str:
        return self.name

class ExpectCount(Enum):
    ZERO = 1
    AT_LEAST_ONE = 2

class ConfigLocation(Enum):
    FILE = 1
    ENV_VAR = 2

class TestUtil:
    @staticmethod
    def get_sponge_log_dir(job_mode: JobMode, job_name: str) -> str:
        artifacts_dir = os.environ.get('KOKORO_ARTIFACTS_DIR')
        if not artifacts_dir:
            raise ValueError('Env var KOKORO_ARTIFACTS_DIR is not defined')
        sponge_log_dir = os.path.join(artifacts_dir, job_mode, job_name)
        os.makedirs(sponge_log_dir, exist_ok = True)
        return sponge_log_dir
