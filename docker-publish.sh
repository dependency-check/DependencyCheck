#!/usr/bin/env bash
set -euo pipefail
function mvn_prop() { mvn help:evaluate -q --non-recursive -DforceStdout -Dexpression="$1"; }
read -r VERSION POSTGRES_DRIVER_VERSION MYSQL_DRIVER_VERSION <<< "$(mvn_prop project.version) $(mvn_prop driver.postgresql.version) $(mvn_prop driver.mysql.version)"

if [[ $VERSION = *"SNAPSHOT"* ]]; then
    echo "Do not publish a snapshot version of dependency-check"
    exit 1
fi

# Build args should match ./docker-build.sh so the builder cache is re-used
docker buildx build --pull=false --push --platform linux/amd64,linux/arm64 . \
    --build-arg "VERSION=$VERSION" --build-arg "POSTGRES_DRIVER_VERSION=$POSTGRES_DRIVER_VERSION" --build-arg "MYSQL_DRIVER_VERSION=$MYSQL_DRIVER_VERSION" \
    --tag owasp/dependency-check:$VERSION \
    --tag owasp/dependency-check:latest
