#!/bin/bash

# Fail on any error.
set -eo pipefail

tar xvzf "${KOKORO_BLAZE_DIR}"/lightfoot_test_source/blaze-genfiles/third_party/ebpf_transport_monitoring/lightfoot_build.tar.gz

exec bash test.sh


