#!/bin/bash
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

set -ex
cd "$(dirname "$0")"


##
#
# Environment Variables (required):
#
# JOB_MODE: 'integration' for stable or 'integration-dev' for adhoc experimental
# LANGUAGE: 'java' | 'go' | 'cpp' | 'interop'
#
##

PROJECT=microsvcs-testing
CLUSTER=grpc-o11y-integration-testing-cluster
ZONE=us-central1-c
RELEASE=1.53.0-dev
TEST_DIR=`realpath ../../observability/test`

if [ -z "${JOB_MODE}" ] || [ -z "${LANGUAGE}" ] ; then
  echo "Error: env var JOB_MODE and LANGUAGE are required."
  exit 1
fi

if [ -z "${KOKORO_ARTIFACTS_DIR}" ] ; then
  echo "Error: env var KOKORO_ARTIFACTS_DIR is not set."
  exit 1
fi



##
#
# Install pre-requisites and set up environment
#
##

gcloud config set project ${PROJECT}

sudo apt-get -qq update
sudo apt-get -qq install -y \
  google-cloud-sdk-gke-gcloud-auth-plugin \
  kubectl clang

# Install Python packages
python3 --version
python3 -m pip install -r requirements.txt

# Install Go
curl -sSL https://go.dev/dl/go1.17.13.linux-amd64.tar.gz -o /tmp/go1.17.13.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf /tmp/go1.17.13.linux-amd64.tar.gz
export PATH=${PATH}:/usr/local/go/bin

# Configure GKE and docker auth
export USE_GKE_GCLOUD_AUTH_PLUGIN=True
gcloud container clusters get-credentials ${CLUSTER} --zone ${ZONE}
gcloud auth configure-docker

# TODO(stanleycheung): find a more appropriate dir
export REPOS_BASE_DIR=${KOKORO_ARTIFACTS_DIR}/github



##
#
# Build TestService client/server binaries for each language
#
##

build_java () {
  mkdir -p ${REPOS_BASE_DIR}/grpc-java
  git clone https://github.com/stanley-cheung/grpc-java ${REPOS_BASE_DIR}/grpc-java
  (cd ${REPOS_BASE_DIR}/grpc-java && \
    git checkout o11y-testing-${JOB_MODE} && \
    git log -1 --oneline && \
    ./gradlew installDist -x test -PskipCodegen=true -PskipAndroid=true)
}

build_go () {
  mkdir -p ${REPOS_BASE_DIR}/grpc-go
  git clone https://github.com/stanley-cheung/grpc-go ${REPOS_BASE_DIR}/grpc-go
  (cd ${REPOS_BASE_DIR}/grpc-go && \
    git checkout o11y-testing-${JOB_MODE} && \
    git log -1 --oneline && \
    go build -o interop/observability/server/ interop/observability/server/server.go && \
    go build -o interop/observability/client/ interop/observability/client/client.go)
}

build_cpp () {
  mkdir -p ${REPOS_BASE_DIR}/grpc
  git clone https://github.com/stanley-cheung/grpc ${REPOS_BASE_DIR}/grpc
  (cd ${REPOS_BASE_DIR}/grpc && \
    git checkout o11y-testing-${JOB_MODE} && \
    git log -1 --oneline && \
    git submodule update --init && \
    ./tools/bazel build test/cpp/interop:interop_test)
}

docker_image_tag () {
  export TAG_NAME=gcr.io/${PROJECT}/grpc-observability/testing/${JOB_MODE}-${LANGUAGE}:${RELEASE}
}

docker_java () {
  docker_image_tag
  (cd ${REPOS_BASE_DIR}/grpc-java && \
    ./buildscripts/observability-test/build_docker.sh && \
    docker push -q ${TAG_NAME})
}

docker_go () {
  docker_image_tag
  (cd ${REPOS_BASE_DIR}/grpc-go && \
    ./interop/observability/build_docker.sh && \
    docker push -q ${TAG_NAME})
}

docker_cpp () {
  docker_image_tag
  (cd ${REPOS_BASE_DIR}/grpc)
}

if [ "${LANGUAGE}" = 'java' ] ; then
  build_java
  docker_java

elif [ "${LANGUAGE}" = 'go' ] ; then
  build_go
  docker_go

elif [ "${LANGUAGE}" = 'cpp' ] ; then
  build_cpp
  docker_cpp

elif [ "${LANGUAGE}" = 'interop' ] ; then
  build_go
  build_java
fi



##
#
# Main
#
##

# Run observability test job
${TEST_DIR}/o11y_tests_manager.py --job_mode ${JOB_MODE} --language ${LANGUAGE}
