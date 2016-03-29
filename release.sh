#!/bin/bash
set -e

latest_tag=$(git tag -l "v*" | sort | tail -n 1)
[ "$latest_tag" != "" ] || { echo "Failed to find a valid tag. Format: 'v#.#.#'"; exit 1; }

head_sha=$(git rev-parse HEAD)
tag_sha=$(git show-ref $latest_tag | cut -d ' ' -f 1)
[ "$head_sha" == "$tag_sha" ] || { echo "Not checked out to the latest version. Fail."; exit 1; }

[ -d build ] || { mkdir build; }
echo "Starting to build version $latest_tag"
goxc -d build/ -pv $latest_tag

tarball=$(ls -1 build/$latest_tag/*amd64.tar.gz)
s3_path="s3://netlify-infrastructure/"

echo "uploading $tarball -> $s3_path"
aws s3 cp $tarball $s3_path
