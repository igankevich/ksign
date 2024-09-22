#!/bin/sh
. ./ci/preamble.sh
image=ghcr.io/igankevich/ksign-ci:latest
docker build --tag $image - <ci/Dockerfile
docker push $image
