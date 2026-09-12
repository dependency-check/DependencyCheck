Yarn Audit Analyzer
================

Uses the Yarn CLI `npm audit` command to analyze `yarn.lock` files and retrieve vulnerabilities from the [NPM Audit](https://www.npmjs.com/) APIs.

Supports Yarn v2.4.0+ (Berry) and is corepack-aware, Yarn v4+ recommended. Yarn Classic (v1) is no longer supported 
due to its dependence on deprecated/decommissioned NPM Audit APIs, and EOL Yarn Berry versions v2 - v3 will only 
function as long as these legacy NPM Audit APIs remain available. They have undergone repeated "brown outs" in 2026 
and are likely to go offline permanently at any time, see [discussion here](https://github.com/dependency-check/DependencyCheck/issues/8423).

Files Types Scanned: package.json, yarn.lock
