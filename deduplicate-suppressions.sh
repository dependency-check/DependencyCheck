#!/bin/bash
# Script to synchronize suppressions between base and generated files

set -e

BASE_SUPPRESSION="core/src/main/resources/dependencycheck-base-suppression.xml"
MODE="${1:-analyzer}"

if [ "$MODE" = "--help" ] || [ "$MODE" = "-h" ]; then
    echo "Usage: $0 [analyzer|deduplicator] [--non-interactive]"
    echo ""
    echo "Modes:"
    echo "  analyzer      - Analyze git history for modified/deleted suppressions (recommended)"
    echo "  deduplicator  - Find exact duplicates between files"
    echo ""
    echo "Options:"
    echo "  --non-interactive - Remove all without prompting"
    echo ""
    echo "Examples:"
    echo "  $0                            # Run analyzer in interactive mode"
    echo "  $0 analyzer --non-interactive # Run analyzer and auto-remove all"
    echo "  $0 deduplicator               # Run old duplicate detection"
    exit 0
fi

# Determine which tool to run
if [ "$MODE" = "deduplicator" ]; then
    MAIN_CLASS="org.owasp.dependencycheck.utils.SuppressionDeduplicator"
    shift # Remove 'deduplicator' from args
elif [ "$MODE" = "analyzer" ] || [ "$MODE" = "--non-interactive" ]; then
    MAIN_CLASS="org.owasp.dependencycheck.utils.SuppressionSyncAnalyzer"
    if [ "$MODE" = "analyzer" ]; then
        shift # Remove 'analyzer' from args
    fi
else
    echo "Unknown mode: $MODE"
    echo "Run '$0 --help' for usage"
    exit 1
fi

echo "Building utils module..."
mvn -pl utils clean compile -q

echo ""
echo "Running synchronization tool..."
mvn -pl utils exec:java \
    -Dexec.mainClass="$MAIN_CLASS" \
    -Dexec.args="$BASE_SUPPRESSION $*"

echo ""
echo "Done!"
