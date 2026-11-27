#!/usr/bin/env bash
set -euo pipefail

git checkout main
git pull --rebase

SNAPSHOT=$(./mvnw help:evaluate -q --non-recursive -DforceStdout -Dexpression=project.version)
RELEASE=${SNAPSHOT/-SNAPSHOT/}

git checkout -b "release-$RELEASE"

./mvnw release:prepare --no-transfer-progress --batch-mode
./mvnw release:clean --no-transfer-progress --batch-mode

git push origin "release-$RELEASE"

git checkout main

git branch -D "release-$RELEASE"