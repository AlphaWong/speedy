#!/usr/bin/env bash

set -e
set -x

PROJECT=speedy
WORKSPACE=/go/src/github.com/netlify/$PROJECT

docker run \
	--volume $(pwd):$WORKSPACE \
	--workdir $WORKSPACE \
	--rm \
	calavera/go-glide:v0.12.2 script/test.sh $PROJECT
