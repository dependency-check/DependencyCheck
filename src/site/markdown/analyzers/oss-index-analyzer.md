OSS Index Analyzer
================

Uses the [Sonatype Guide OSS Index](https://www.sonatype.com/products/sonatype-guide/oss-index-users) APIs to report on
vulnerabilities not found in the NVD. The collection of identified [PURL/Package URL](https://github.com/package-url/purl-spec)
identifiers are submitted to the OSS Index for analysis and the resulting
identified vulnerabilities are included in the report. In addition, vulnerabilities
found in both the NVD and OSS Index may have additional references added.

This analyzer requires an internet connection, and authentication is mandatory. If no credentials are provided, this 
analyzer will be disabled. Review the configuration for the specific dependency-check integration used for more information 
on how to configure the URL and credentials for this analyzer.

### Sonatype Guide Migration

During 2026, the Sonatype OSS Index API is [being migrated](https://www.sonatype.com/products/sonatype-guide/oss-index-users) to become
part of the [Sonatype Guide](https://guide.sonatype.com/) platform.

During this migration users will need to make some minor changes.
- For **existing** users (have an existing legacy OSS Index account and API token)
  - _After_ April 1, 2026
    - login with OSS Index account credentials to the Sonatype Guide platform to validate your account has been migrated
    - migrate OSS Index analyzer base URL to Sonatype Guide platform
      - override Dependency-Check configuration OR
      - upgrade to Dependency-Check `12.2.1`+ (if using defaults)
    - review API usage within Sonatype Guide to determine whether continued free usage is possible (new API limits apply from April 28 2026 onwards)
      - consider [cache/restore of Dependency-Check's data directory](../data/cacheh2.md) between runs to retain the OSS Index cache, and reduce API load 
  - _Before_ December 31, 2026 
    - migrate to using a Sonatype Guide API token for authentication rather than the legacy OSS Index API token
- For **new** users
  - sign up for Sonatype Guide directly
  - use a Sonatype Guide API token as the OSS Index `password` for authentication (`username` is optional)

For more details on this migration see:
- [Sonatype OSS Index product page](https://www.sonatype.com/products/sonatype-guide/oss-index-users)
- [Sonatype Migration timeline](https://help.sonatype.com/en/oss-index-migration-to-sonatype-guide.html)
- [Using Sonatype Guide personal access tokens for OSS Index API](https://help.sonatype.com/en/using-guide-personal-access-tokens-with-oss-index-api-integrations.html)
