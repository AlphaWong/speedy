#!/usr/bin/env bash

set -e
set -x

PROJECT=speedy
WORKSPACE=/go/src/github.com/netlify/$PROJECT

#
# start dependent containers
#
DB_VOLUME=`docker volume create`

#
# cleanup other containers
#
function cleanup {
	docker volume rm ${DB_VOLUME} || true
	rm -rf vendor
}
trap cleanup EXIT

docker run \
	--volume $(pwd):$WORKSPACE \
	--volume $DB_VOLUME:$WORKSPACE/vendor \
	--workdir $WORKSPACE \
	--rm \
	calavera/go-lide:v0.12.2 script/test.sh $PROJECT
