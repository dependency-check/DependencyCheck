Yarn Audit Analyzer
================

Uses the Yarn CLI `audit` command to analyze `yarn.lock` files and retrieve vulnerabilities from the [NPM Audit](https://www.npmjs.com/) APIs.

Supports Yarn v2+ (Berry) and is corepack-aware. Yarn v1 (Classic) is no longer supported due to its use of a removed NPM Audit API.

Files Types Scanned: package.json, yarn.lock
