#!/bin/bash
set -euo pipefail

VERSION=$(mvn -q \
    -Dexec.executable="echo" \
    -Dexec.args='${project.version}' \
    --non-recursive \
   exec:exec)

FILE=./cli/target/dependency-check-$VERSION-release.zip
if [ ! -f "$FILE" ]; then
    echo "$FILE does not exist - run 'mvn package' first"
    exit 1
fi

if ! docker info -f '{{ .DriverStatus }}' | grep "driver-type io.containerd.snapshotter" >/dev/null; then
    echo "Docker Engine is not running with the containerd snapshotter - this is currently needed to build and test ODC multi-platform images using docker buildx."
    echo "If using Docker Desktop, enable \"Use containerd for pulling and storing images\" per https://docs.docker.com/desktop/settings-and-maintenance/settings/#general"
    echo "For more technical information on Docker Engine, see https://docs.docker.com/engine/storage/containerd/"
    exit 1
fi

extra_tag_args="$([[ ! $VERSION = *"SNAPSHOT"* ]] && echo "--tag owasp/dependency-check:latest" || echo "")"

docker buildx build --pull --load --platform linux/amd64,linux/arm64 . \
    --build-arg VERSION=$VERSION \
    --tag owasp/dependency-check:$VERSION ${extra_tag_args}
