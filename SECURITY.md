# Security Policy

## Supported Versions

| Version   | Supported          |
| ----------|--------------------|
| 10.0.2+   | :white_check_mark: |
| <= 10.0.1 | :x:                |

## Reporting a Vulnerability

If a security vulnerability is identified in dependency-check please
open an [issue](https://github.com/jeremylong/DependencyCheck/issues/new/choose)
and/or submit a PR to resolve the identified vulnerability.

The team is very responsive to reported vulnerabilities - historically having reported issues resolved in 30 days or less.

Note - there are several vulnerable test dependencies and test resources. These are never executed or included in a release; these vulnerable resources are present so that the functionality of dependency-check can be tested (i.e. it correctly identifies the given vulnerable test dependency).
