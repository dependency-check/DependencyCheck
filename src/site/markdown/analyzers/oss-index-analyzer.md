OSS Index Analyzer
================

Uses the [OSS Index](https://ossindex.sonatype.org/) APIs to report on
vulnerabilities not found in the NVD. The collection of identified Package-URL
identifiers are submitted to the OSS Index for analysis and the resulting
identified vulnerabilities are included in the report. In addition, vulnerabilities
found in both the NVD and OSS Index may have additional references added.

This analyzer requires an Internet connection.

Sonatype [announced](https://ossindex.sonatype.org/doc/auth-required) that OSS Index requires authentication.

You can get an API Token following these steps:
1. [Sign In](https://ossindex.sonatype.org/user/signin) or [Sign Up](https://ossindex.sonatype.org/user/register) for free.
2. Get the API Token from user Settings.

If no credentials are provided, this analyzer will be disabled.
