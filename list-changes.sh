#!/usr/bin/env bash
set -uo pipefail
function commits_for() {
  ##https://blogs.sap.com/2018/06/22/generating-release-notes-from-git-commit-messages-using-basic-shell-commands-gitgrep/
  git --no-pager log "$(git describe --tags --abbrev=0)..HEAD" --pretty=format:" - %s" \
    | grep -E -v '^ - build: (prepare|release)' \
    | grep -E "^ - $1" \
    | sed -E 's/#([0-9]+)/[#\1](https:\/\/github.com\/dependency-check\/DependencyCheck\/pull\/\1)/g' \
    | sort
}

printf "\n## [Version X.Y.Z](https://github.com/dependency-check/DependencyCheck/releases/tag/vX.Y.Z) (yyyy-MM-dd)\n\n"
for prefix in "feat" "fix" "perf" "docs" "chore" "refactor" "test" "ci" "build"; do
  commits_for "$prefix"
done
printf "\nSee the full listing of [changes](https://github.com/dependency-check/DependencyCheck/milestone/CHANGEME?closed=1)\n\n"
