#!/bin/bash -e

VERSION=$(mvn -q \
    -Dexec.executable="echo" \
    -Dexec.args='${project.version}' \
    --non-recursive \
    org.codehaus.mojo:exec-maven-plugin:1.3.1:exec)

FILE=./cli/target/dependency-check-$VERSION-release.zip
if [ -f "$FILE" ]; then
    extra_tag_args="$([[ ! $VERSION = *"SNAPSHOT"* ]] && echo "--tag owasp/dependency-check:latest" || echo "")"

    docker buildx build --pull --load --platform linux/amd64,linux/arm64 . \
      --build-arg VERSION=$VERSION \
      --tag owasp/dependency-check:$VERSION ${extra_tag_args}
else 
    echo "$FILE does not exist - run 'mvn package' first"
    exit 1
fi
