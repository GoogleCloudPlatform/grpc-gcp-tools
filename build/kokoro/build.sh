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

docker_image_tag () {
  SHORT_HASH=`git rev-parse --short HEAD`
  IMAGE_NAME=gcr.io/${PROJECT}/grpc-observability/testing/${JOB_MODE}-${LANG}
  # TODO(stanleycheung): use a more descriptive name than TAG_NAME, need to change all repos
  export TAG_NAME=${IMAGE_NAME}:${SHORT_HASH}
  IMAGE_TAG_LATEST=${IMAGE_NAME}:latest
}

check_docker_image() {
  gcloud container images describe ${TAG_NAME} && echo "Image already built, skipping..."
}

prepare_docker_image() {
  mkdir -p ${REPOS_BASE_DIR}/${REPO_NAME}
  git clone --single-branch --branch ${GIT_CLONE_BRANCH} ${GIT_CLONE_PATH} ${REPOS_BASE_DIR}/${REPO_NAME}
  cd ${REPOS_BASE_DIR}/${REPO_NAME}
  docker_image_tag
  check_docker_image || ( \
    $BUILD_DOCKER_FUNC && \
    docker tag ${TAG_NAME} ${IMAGE_TAG_LATEST} && \
    docker push ${TAG_NAME} && \
    docker push ${IMAGE_TAG_LATEST} )
  export $DOCKER_IMAGE_ENV_VAR_NAME=${TAG_NAME}
}

docker_build_cmd_java () {
  ./buildscripts/observability-test/build_docker.sh
}
docker_build_cmd_go () {
  ./interop/observability/build_docker.sh
}
docker_build_cmd_cpp () {
  ./tools/dockerfile/observability-test/cpp/build_docker.sh
}

build_java () {
  REPO_NAME=grpc-java
  GIT_CLONE_PATH=${GRPC_JAVA_REPO_PATH}
  GIT_CLONE_BRANCH=${GRPC_JAVA_REPO_BRANCH}
  LANG='java'
  BUILD_DOCKER_FUNC=docker_build_cmd_java
  DOCKER_IMAGE_ENV_VAR_NAME=OBSERVABILITY_TEST_IMAGE_JAVA
  prepare_docker_image
}

build_go () {
  REPO_NAME=grpc-go
  GIT_CLONE_PATH=${GRPC_GO_REPO_PATH}
  GIT_CLONE_BRANCH=${GRPC_GO_REPO_BRANCH}
  LANG='go'
  BUILD_DOCKER_FUNC=docker_build_cmd_go
  DOCKER_IMAGE_ENV_VAR_NAME=OBSERVABILITY_TEST_IMAGE_GO
  prepare_docker_image
}

build_cpp () {
  REPO_NAME=grpc
  GIT_CLONE_PATH=${GRPC_GRPC_REPO_PATH}
  GIT_CLONE_BRANCH=${GRPC_GRPC_REPO_BRANCH}
  LANG='cpp'
  BUILD_DOCKER_FUNC=docker_build_cmd_cpp
  DOCKER_IMAGE_ENV_VAR_NAME=OBSERVABILITY_TEST_IMAGE_CPP
  prepare_docker_image
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



##
#
# Main
#
##

# Run observability test job
${TEST_DIR}/o11y_tests_manager.py --job_mode ${JOB_MODE} --language ${LANGUAGE}
