#!/bin/bash -e

VERSION=$(mvn -q \
    -Dexec.executable="echo" \
    -Dexec.args='${project.version}' \
    --non-recursive \
   exec:exec)

SCAN_TARGET="./cli/target/release/lib"

if [ ! -d "$SCAN_TARGET" ]; then 
  echo "Scan target does not exist: $SCAN_TARGET"
  exit 1
fi

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
    
