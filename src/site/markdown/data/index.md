Remote Data Sources
====================

Dependency-check, by default, requires internet access to several externally hosted resources.

### External Hosts

Dependency-Check may contact the following external hosts depending on the enabled analyzers and configuration:

| Purpose                              | Hostname                               | Relevant Analyzers                 | Primary Ecosystem | Configurable / Proxyable? | Mirrorable? |
|--------------------------------------|----------------------------------------|------------------------------------|-------------------|---------------------------|-------------|
| NVD API (CVE & CPE data)             | `services.nvd.nist.gov`                | All                                | All               | ✅                         | ✅           |
| CISA Known Exploited Vulnerabilities | `www.cisa.gov`                         | Known Exploited Vulnerabilities    | All               | ✅                         | ✅           |
| ODC Hosted suppressions file         | `dependency-check.github.io`           | Hosted Suppressions                | All               | ✅                         | ✅           |
| Sonatype OSS Index API               | `ossindex.sonatype.org`                | OSS Index                          | All               | ✅                         | ❌           |
| RetireJS definitions                 | `raw.githubusercontent.com`            | RetireJS                           | Javascript        | ✅                         | ✅           |
| NPM audit advisories                 | `registry.npmjs.org`                   | Node Audit, Yarn Audit, PNPM Audit | Javascript        | ✅                         | ❌           |
| Maven Central search                 | `search.maven.org` / `repo1.maven.org` | Central                            | Java / JVM        | ✅                         | ❌           |
| Ruby Security advisories             | `github.com`                           | Ruby Bundle Audit                  | Ruby              | *️⃣                       | *️⃣         |
| Elixir Security advisories           | `github.com`                           | Elixir Mix Audit                   | Elixir            | *️⃣                       | *️⃣         |
| Scarf telemetry (optional)           | `api.scarf.sh`                         | N/A                                | All               | ❌                         | ❌           |

#### Methodology

**Configurable / Proxyable** - can be configured directly within ODC to use an alternate URL, e.g some kind of caching/forwarding proxy (*️⃣ - may be possible via third-party tool configuration)
**Mirrorable** - data source can be mirrored somewhere locally to completely avoid direct access (*️⃣ - requires alternate data source/analyzer)

Some entries (such as NPM audit data) are accessed indirectly via ecosystem-specific analyzers or external CLI tools rather
than by the Dependency-Check core itself.

To avoid documenting incorrect or misleading network dependencies, only hosts that could be reasonably verified through
code inspection, configuration defaults, or authoritative project documentation are included.

### The NVD Database

OWASP dependency-check maintains a local copy of the NVD API's CVE data hosted by NIST. By default,
a local [H2 database](http://www.h2database.com/html/main.html) instance is used.
As each instance maintains its own copy of the NVD the machine will need access
to nvd.nist.gov in order to download the NVD data feeds. While the initial download of the NVD
data feed is large, if after the initial download the tool is run at least once every seven
days only two small XML files containing the recent modifications will need to be downloaded.

In some installations OpenJDK may not be able to access the NVD API. Please see the
[TLS Failures article](./tlsfailure.html) for more information.

If your build servers are using dependency-check and are unable to access the Internet you
have a few options:

1. Configure the [proxy settings](proxy.html) so that the build server can access the Internet
2. [Mirror the NVD](./mirrornvd.html) locally within your organization
3. Build the H2 database on one node and [cache the H2 database](./cacheh2.md).
4. Use a more robust [centralized database](./database.html) with a single update node
5. In GitHub Actions utilize the cache action; [example here](./cache-action.md).

### CISA Known Exploited Vulnerabilities

With version 8.0.0 access to the CISA Known Exploited Vulnerabilities Catalog is required.
If running on a system with limited network access there are three options:

1. Add `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` to the allow list.
2. Mirror `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` locally.
3. Disable the CISA Known Exploited Vulnerabilities Analyzer.

### Retire JS Repository

The RetireJS Analyzers must download the RetireJS Repository from `https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json`. If this is blocked users
must either mirror the repository or disable the Retire JS Analyzer.

The Retire JS repository can be configured using the `retireJsUrl` configuration option.
See the configuration for the specific dependency-check client used for more information.

### Hosted base suppressions file

For a faster roundtrip time ([issue #4723](https://github.com/dependency-check/DependencyCheck/issues/4723)) to get false-positive report 
solution out to the users dependency-check starting from version 8.0.0 is using an online hosted 
[suppressions file](https://dependency-check.github.io/DependencyCheck/suppressions/publishedSuppressions.xml). 
For environments with constraints to internet access this file can be locally mirrored by customizing the hostedsuppressions file URL.
See the tool-specific configuration documentation on the [github pages](https://dependency-check.github.io/DependencyCheck/index.html) 
for the exact advanced configuration flag to specify the custom location.
Failure to download the hosted suppressions file will result in only a warning from the tool, but may result in false positives 
being reported by your scan that have already been mitigated by the hosted suppressions file.

### Maven Central Repository

Using CLI, Docker or Ant plugin scanners to scan Java / JVM artifacts without access to reach the [Maven Central Repository](http://search.maven.org) 
may result in significant numbers of false positives and negatives. 

This is because many JAR files do not contain the necessary POM metadata evidence required to accurately identify a library.

If Maven Central cannot be reached, it is highly recommended to setup a Nexus or Artifactory server within your 
organization and to configure dependency-check to use the alternative Nexus or Artifactory analyzers with your local server in place of the Maven Central analyzer.

**Notes:**
1. When using Maven or Gradle plugins - there is typically little benefit to setting up a Nexus or Artifactory server 
   for use by dependency-check - except when scanning artfifacts such as "uber-jars". This is because the Maven and 
   Gradle plugins typically provide the necessary metadata directly, and looking inside JAR files is unnecessary.
2. Even with a Nexus or Artifactory server configured it is possible for dependency-check CLI to be re-directed to other
   repositories on the Internet to download the actual POM file; this can happen due to a rare circumstance where an 
   Nexus instance used by dependency-check was not the instance of Nexus used to build the application (i.e. the 
   dependencies were not actually present in the Nexus used by dependency-check).

### Sonatype OSS Index

OWASP dependency-check includes support to consult the [Sonatype OSS Index](https://ossindex.sonatype.org)
to enrich the report with supplemental vulnerability information.

For more details on this integration see [Sonatype OSS Index](./ossindex.html).

### Telemetry

See the [telemetry documentation](../general/telemetry.html) for more information about telemetry data collection.
