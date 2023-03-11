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
python3 -m pip install -r requirements.lock

# Install Go
curl -sSL https://go.dev/dl/go1.17.13.linux-amd64.tar.gz -o /tmp/go1.17.13.linux-amd64.tar.gz
echo '0b5858bc0f90dd17536df3a4d7635cc576b2c507 /tmp/go1.17.13.linux-amd64.tar.gz' | sha1sum -c -
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


# TODO(stanleycheung): ideally the Kokoro job should be initiated from each lang's repo
# so that we don't need to keep track of these details here.

build_java () {
  mkdir -p ${REPOS_BASE_DIR}/grpc-java
  git clone --single-branch --branch ${GRPC_JAVA_REPO_BRANCH} \
    ${GRPC_JAVA_REPO_PATH} ${REPOS_BASE_DIR}/grpc-java
  cd ${REPOS_BASE_DIR}/grpc-java
  LANG='java' docker_image_tag
  check_docker_image || ( \
    ./buildscripts/observability-test/build_docker.sh && \
    docker push ${TAG_NAME} )
  export OBSERVABILITY_TEST_IMAGE_JAVA=${TAG_NAME}
}

build_go () {
  mkdir -p ${REPOS_BASE_DIR}/grpc-go
  git clone --single-branch --branch ${GRPC_GO_REPO_BRANCH} \
    ${GRPC_GO_REPO_PATH} ${REPOS_BASE_DIR}/grpc-go
  cd ${REPOS_BASE_DIR}/grpc-go
  LANG='go' docker_image_tag
  check_docker_image || ( \
    ./interop/observability/build_docker.sh && \
    docker push ${TAG_NAME} )
  export OBSERVABILITY_TEST_IMAGE_GO=${TAG_NAME}
}

build_cpp () {
  mkdir -p ${REPOS_BASE_DIR}/grpc
  git clone --single-branch --branch ${GRPC_GRPC_REPO_BRANCH} \
    ${GRPC_GRPC_REPO_PATH} ${REPOS_BASE_DIR}/grpc
  cd ${REPOS_BASE_DIR}/grpc
  LANG='cpp' docker_image_tag
  check_docker_image || ( \
    ./tools/dockerfile/observability-test/cpp/build_docker.sh && \
    docker push ${TAG_NAME} )
  export OBSERVABILITY_TEST_IMAGE_CPP=${TAG_NAME}
}

check_docker_image() {
  gcloud container images describe ${TAG_NAME} && echo "Image already built, skipping..."
}

docker_image_tag () {
  SHORT_HASH=`git rev-parse --short HEAD`
  export TAG_NAME=gcr.io/${PROJECT}/grpc-observability/testing/${JOB_MODE}-${LANG}:${SHORT_HASH}
}

if [ "${LANGUAGE}" = 'java' ] ; then
  build_java

elif [ "${LANGUAGE}" = 'go' ] ; then
  build_go

elif [ "${LANGUAGE}" = 'cpp' ] ; then
  build_cpp

elif [ "${LANGUAGE}" = 'interop' ] ; then
  build_go
  build_java
  build_cpp
fi

docker ps -a


##
#
# Main
#
##

# Run observability test job
${TEST_DIR}/o11y_tests_manager.py --job_mode ${JOB_MODE} --language ${LANGUAGE}

docker ps -a
