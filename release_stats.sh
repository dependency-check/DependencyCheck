#!/usr/bin/env bash
set -euo pipefail
curl   -H "Accept: application/vnd.github.v3+json"   https://api.github.com/repos/dependency-check/DependencyCheck/releases| jq -r '.[] | (.tag_name + "," + (.assets[]|(.name+","+(.download_count|tostring))))' | grep -v \.asc | sort