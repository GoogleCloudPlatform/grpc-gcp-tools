#!/bin/bash

set -ex
cd "$(dirname "$0")"

export PROJECT=`gcloud config get-value project`
export PROJNUM=`gcloud projects describe $PROJECT --format="value(projectNumber)"`
export SERVER_IMAGE=gcr.io/microsvcs-testing/grpc-observability/testing/integration-dev-go:1.53.0-dev
export CLIENT_IMAGE=gcr.io/microsvcs-testing/grpc-observability/testing/integration-dev-go:1.53.0-dev
export JOB_MODE=integration-manual

cat ./gke-deployment.yaml | envsubst | kubectl apply -f -
