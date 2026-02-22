#!/usr/bin/env bash
set -euo pipefail
##https://blogs.sap.com/2018/06/22/generating-release-notes-from-git-commit-messages-using-basic-shell-commands-gitgrep/
git --no-pager log "$(git describe --tags --abbrev=0)..HEAD" --pretty=format:" - %s" \
  | grep -v ' - Bump' \
  | sed -E 's/#([0-9]+)/[#\1](https:\/\/github.com\/dependency-check\/DependencyCheck\/pull\/\1)/g'
