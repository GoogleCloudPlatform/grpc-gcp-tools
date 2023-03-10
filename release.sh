#!/bin/bash
if [ "$1" == "" ]; then
  echo "USAGE:  $0 TOOL NAME" >&2
  exit 1
fi

if [ ! -e $1 ]; then
  echo $1": Tool not found." >&2
  exit 1
fi

set -ex

build_dp_check() {
  cd dp_check && CGO_ENABLED=0 go build dp_check.go netlink_linux.go
  file dp_check | grep 'statically linked'
  if [ $? != 0 ]; then
    echo "dp_check binary is not statically linked"
    exit 1
  fi
}

eval "build_$1"
