#!/bin/bash

set -e

cd "${KOKORO_ARTIFACTS_DIR}/github/grpc-gcp-tools/build/kokoro"
./build.sh
