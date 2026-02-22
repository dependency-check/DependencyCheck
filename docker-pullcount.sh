#!/usr/bin/env bash
set -euo pipefail
curl -s https://hub.docker.com/v2/repositories/owasp/dependency-check/ | python3 -c "import sys, json; print(json.load(sys.stdin)['pull_count'])"