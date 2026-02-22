#!/usr/bin/env bash
set -euo pipefail
VERSION="$(mvn help:evaluate -q --non-recursive -DforceStdout -Dexpression=project.version)"

SCAN_TARGET="./cli/target/release/lib"

if [ ! -d "$SCAN_TARGET" ]; then 
    echo "Scan target does not exist: $SCAN_TARGET"
    exit 1
fi

if [ -f "$HOME/OWASP-Dependency-Check/reports/dependency-check-report.json" ]; then
    echo "Deleting previous report"
    rm "$HOME/OWASP-Dependency-Check/reports/dependency-check-report.json"
fi

if [ -f "$HOME/OWASP-Dependency-Check/reports/odc.log" ]; then
    echo "Deleting previous log"
    rm "$HOME/OWASP-Dependency-Check/reports/odc.log"
fi

cd $SCAN_TARGET
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
if [ -f "$HOME/OWASP-Dependency-Check/reports/odc.log" ]; then
    rm "$HOME/OWASP-Dependency-Check/reports/odc.log"
fi

docker run --rm \
    -e user=$USER \
    -u $(id -u ${USER}):$(id -g ${USER}) \
    --volume $(pwd):/src:z \
    --volume "$DATA_DIRECTORY":/usr/share/dependency-check/data:z \
    --volume "$REPORT_DIRECTORY":/report:z \
    owasp/dependency-check:$VERSION \
    --scan /src \
    --format "JSON" \
    --project "test scan" \
    --disableCentral \
    --disableOssIndex \
    --out /report \
    --log /report/odc.log \
    --nvdDatafeed https://dependency-check.github.io/DependencyCheck/hb_nvd/

# return to original working directory
cd -

echo ""
grep -oF "dependency-check-core-$VERSION.jar" $HOME/OWASP-Dependency-Check/reports/dependency-check-report.json  > /dev/null 2>&1
if [[ "$?" -eq 0 ]] ; then
    echo "SUCCESS - dependency-check docker test passed"
else
    echo "FAILED - dependency-check docker test failed"
    exit 1
fi
