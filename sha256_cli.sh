#!/usr/bin/env bash
set -euo pipefail
ver=$(curl -s https://dependency-check.github.io/DependencyCheck/current.txt)
echo "Version $ver"
wget -q https://github.com/dependency-check/DependencyCheck/releases/download/v$ver/dependency-check-$ver-release.zip
shasum -a 256 dependency-check-$ver-release.zip
rm dependency-check-$ver-release.zip
