#!/bin/bash -e

VERSION=$(mvn -q \
    -Dexec.executable="echo" \
    -Dexec.args='${project.version}' \
    --non-recursive \
   exec:exec)

if [[ $VERSION = *"SNAPSHOT"* ]]; then
    echo "Do not publish a snapshot version of dependency-check"
    exit 1
fi

# Build args should match ./build-docker.sh so the builder cache is re-used
docker buildx build --push --platform linux/amd64,linux/arm64 . \
    --build-arg VERSION=$VERSION \
    --tag owasp/dependency-check:$VERSION \
    --tag owasp/dependency-check:latest
