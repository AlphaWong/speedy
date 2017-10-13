#!/bin/bash

S3_PATH="s3://netlify-infrastructure/"

[ $# -eq 1 ] || { echo "Must provide a binary to build"; exit 1; }

path_to_binary="$1"
[ -e "$path_to_binary" ] || { echo "Failed to find binary at '$path_to_binary'"; exit 1; }
binary_dir="$(dirname "$path_to_binary")"
binary_name=`basename $path_to_binary`

echo "Moving to build directory: '$binary_dir'"
cd $binary_dir

echo "Checking if this is a clean checkout"
[ "xx$(git status --porcelain | grep -v $binary_name)xx" == "xxxx" ] || { echo "You can only release from a clean checkout"; exit 1; }

commit=$(git rev-parse HEAD)
echo "Checking for this to be a tagged commit: $commit"
tag=$(git show-ref --tags -d | grep $commit)
[ $? -eq 0 ] || { echo "Can't build from untagged commit - skipping release"; exit 0; }

tag=$(echo $tag | cut -d '/' -f 3)
echo "Starting to upload version $tag"
echo "Compressing $binary_name"
mv $binary_name ${binary_name}_${tag}
with_tag="${binary_name}_${tag}"
tarball=$with_tag.tar.gz
tar -czf $tarball $with_tag

echo "Uploading $tarball -> $S3_PATH"
aws s3 cp $tarball $S3_PATH

echo "Upload complete"

