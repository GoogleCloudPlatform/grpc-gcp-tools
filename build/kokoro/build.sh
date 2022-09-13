#!/bin/bash

set -e

gcloud config set project stanleycheung-gke2-dev

gcloud config list

kubectl config view
