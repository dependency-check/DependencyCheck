#!/usr/bin/env bash
set -euo pipefail
VERSION="$(mvn help:evaluate -q --non-recursive -DforceStdout -Dexpression=project.version)"

OWASPDC_DIRECTORY=$HOME/OWASP-Dependency-Check
DATA_DIRECTORY="$OWASPDC_DIRECTORY/data"
REPORT_DIRECTORY="$OWASPDC_DIRECTORY/reports"
CACHE_DIRECTORY="$OWASPDC_DIRECTORY/data/cache"

if [ ! -d "$DATA_DIRECTORY" ]; then
    echo "Initially creating persistent directory: $DATA_DIRECTORY"
    mkdir -p "$DATA_DIRECTORY"
fi

if [ ! -d "$REPORT_DIRECTORY" ]; then
    echo "Initially creating persistent directory: $REPORT_DIRECTORY"
    mkdir -p "$REPORT_DIRECTORY"
fi

if [ ! -d "$CACHE_DIRECTORY" ]; then
    echo "Initially creating persistent directory: $CACHE_DIRECTORY"
    mkdir -p "$CACHE_DIRECTORY"
fi

if [ -f "$HOME/OWASP-Dependency-Check/reports/dependency-check-report.json" ]; then
    rm "$HOME/OWASP-Dependency-Check/reports/dependency-check-report.json"
fi

# Make sure we are using the latest version
# docker pull owasp/dependency-check

docker run -it --rm \
    --volume "$DATA_DIRECTORY":/usr/share/dependency-check/data \
    --volume "$REPORT_DIRECTORY":/report \
    --entrypoint /bin/sh \
    owasp/dependency-check:$VERSION
    
