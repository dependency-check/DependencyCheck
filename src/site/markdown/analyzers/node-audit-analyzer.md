Node Audit Analyzer
================

OWASP dependency-check includes a Node Audit Analyzer that scans `package-lock.json`
and `npm-shrinkwrap.json` files. The analyzer runs [`npm audit`](https://docs.npmjs.com/cli/commands/npm-audit)
against the lock file, returning a list of advisories which get incorporated into the
dependency check reports.

This analyzer is enabled by default and requires:

- The `npm` command must be available - whether from an npm install, a
  [corepack](https://github.com/nodejs/corepack) shim, or the configured
  path to npm setting.
- The machine performing the analysis must be able to reach the npm registry
  (or the registry configured via `.npmrc`).

The analysis is performed against the lock file alone (`npm audit --package-lock-only`);
the project's `node_modules` directory does not need to be installed.

Files Types Scanned: [package-lock.json](https://docs.npmjs.com/files/package-lock.json),
[npm-shrinkwrap.json](https://docs.npmjs.com/cli/configuring-npm/npm-shrinkwrap-json)
