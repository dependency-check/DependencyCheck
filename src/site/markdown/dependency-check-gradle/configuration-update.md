Tasks
====================

Task                                                     | Description
---------------------------------------------------------|-----------------------
[dependencyCheckAnalyze](configuration.html)             | Runs dependency-check against the project and generates a report.
[dependencyCheckAggregate](configuration-aggregate.html) | Runs dependency-check against a multi-project build and generates a report.
dependencyCheckUpdate                                    | Updates the local cache of the NVD data from NIST.
[dependencyCheckPurge](configuration-purge.html)         | Deletes the local copy of the NVD. This is used to force a refresh of the data.

Configuration
====================

```groovy
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:${project.version}'
    }
}
apply plugin: 'org.owasp.dependencycheck'

check.dependsOn dependencyCheckUpdate
```

Property             | Description                        | Default Value
---------------------|------------------------------------|------------------
failOnError          | Fails the build if an error occurs during the dependency-check analysis.                                           | true

#### Example
```groovy
dependencyCheck {
    failOnError=true
}
```

### Proxy Configuration

Config Group | Property          | Description                                | Default Value
-------------|-------------------|--------------------------------------------|------------------
proxy        | server            | The proxy server; see the [proxy configuration](../data/proxy.html) page for more information. | &nbsp;
proxy        | port              | The proxy port.                            | &nbsp;
proxy        | username          | Defines the proxy user name.               | &nbsp;
proxy        | password          | Defines the proxy password.                | &nbsp;
proxy        | nonProxyHosts     | The list of hosts that do not use a proxy. | &nbsp;

#### Example
```groovy
dependencyCheck {
    proxy.server=some.proxy.server
    proxy.port=8989
}
```

### Advanced Configuration

The following properties can be configured in the dependencyCheck task. However, they are less frequently changed.

Config Group | Property          | Description                                                                                                                                                     | Default Value                                                       |
-------------|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------|
nvd          | apiKey            | The API Key to access the NVD API; obtained from https://nvd.nist.gov/developers/request-an-api-key                                                             | &nbsp;                                                              |
nvd          | endpoint          | The NVD API endpoint URL; setting this is uncommon.                                                                                                             | https://services.nvd.nist.gov/rest/json/cves/2.0                    |
nvd          | maxRetryCount     | The maximum number of retry requests for a single call to the NVD API.                                                                                          | 10                                                                  |
nvd          | delay             | The number of milliseconds to wait between calls to the NVD API.                                                                                                | 3500 with an NVD API Key or 8000 without an API Key .               |
nvd          | resultsPerPage    | The number records for a single page from NVD API (must be <=2000).                                                                                             | 2000                                                                |
nvd          | datafeedUrl       | The URL for the NVD API Data feed that can be generated using https://github.com/jeremylong/Open-Vulnerability-Project/tree/main/vulnz#caching-the-nvd-cve-data | &nbsp;           |
nvd          | datafeedUser      | Credentials used for basic authentication for the NVD API Data feed.                                                                                            | &nbsp;                                                              |
nvd          | datafeedPassword  | Credentials used for basic authentication for the NVD API Data feed.                                                                                            | &nbsp;                                                              |
nvd          | datafeedBearerToken  | Credentials used for bearer authentication for the NVD API Data feed.                                                                                        | &nbsp;                                                              |
nvd          | validForHours     | The number of hours to wait before checking for new updates from the NVD. The default is 4 hours.                                                               | 4                                                                   |
data         | directory         | Sets the data directory to hold SQL CVEs contents. This should generally not be changed.                                                                        | ~/.gradle/dependency-check-data/                                    |
data         | driver            | The database driver full classname; note, only needs to be set if the driver is not JDBC4 compliant or the JAR is outside of the class path.                    | &nbsp;                                                              |
data         | driverPath        | The path to the database driver JAR file; only needs to be set if the driver is not in the class path.                                                          | &nbsp;                                                              |
data         | connectionString  | The connection string used to connect to the database. See using a [database server](../data/database.html).                                                    | &nbsp;                                                              |
data         | username          | The username used when connecting to the database.                                                                                                              | &nbsp;                                                              |
data         | password          | The password used when connecting to the database.                                                                                                              | &nbsp;                                                              |
hostedSuppressions | enabled         | Whether the hosted suppressions file will be used.                                                                                                              | true                                                                |
hostedSuppressions | forceupdate     | Sets whether hosted suppressions file will update regardless of the `autoupdate` setting.                                                                       | false                                                               |
hostedSuppressions | url             | The URL to (a mirror of) the hosted suppressions file.                                                                                                          | https://jeremylong.github.io/DependencyCheck/suppressions/publishedSuppressions.xml |
hostedSuppressions | user            | Credentials used for basic authentication for the hosted suppressions file.                                                                                     | &nbsp;                                                              |
hostedSuppressions | password        | Credentials used for basic authentication for the hosted suppressions file.                                                                                     | &nbsp;                                                              |
hostedSuppressions | bearerToken     | Credentials used for bearer authentication for the hosted suppressions file.                                                                                    | &nbsp;                                                              |
hostedSuppressions | validForHours   | The number of hours to wait before checking for new updates of the hosted suppressions file .                                                                   | 2                                                                   |

#### Example
```groovy
dependencyCheck {
    data.directory='d:/nvd'
}
```

### Analyzer Configuration

Cached web datasources for several analyzers are configured inside the `analyzers` section with some properties
taking relevance also in the update task. In addition to the above, the updateTask can be customized for retrieval
of these resources by the following analyzer-specific properties underneath the `analyzers` section.

 Config Group | Property      | Description                                                                                             | Default Value                                                                            |
--------------|---------------|---------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|
 kev          | enabled       | Sets whether the Known Exploited Vulnerability update and analyzer are enabled.                         | true                                                                                     |
 kev          | url           | The URL to (a mirror of) the CISA Known Exploited Vulnerabilities JSON data feed.                       | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json      |
 kev          | user          | Credentials used for basic authentication for the CISA Known Exploited Vulnerabilities JSON data feed.  | &nbsp;                                                                                   |
 kev          | password      | Credentials used for basic authentication for the CISA Known Exploited Vulnerabilities JSON data feed.  | &nbsp;                                                                                   |
 kev          | bearerToken   | Credentials used for bearer authentication for the CISA Known Exploited Vulnerabilities JSON data feed. | &nbsp;                                                                                   |
 kev          | validForHours | The number of hours to wait before checking for new updates of the hosted suppressions file .           | 2                                                                                        |
 retirejs     | enabled       | Sets whether the RetireJS Analyzer should be used / the repository be updated.                          | true                                                                                     |
 retirejs     | retireJsUrl   | The URL to the Retire JS repository.                                                                    | https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json |
retirejs     | user          | Credentials used for basic authentication for the Retire JS repository URL.                             | &nbsp;                                                                                   |
retirejs     | password      | Credentials used for basic authentication for the Retire JS repository URL.                             | &nbsp;                                                                                   |
retirejs     | bearerToken   | Credentials used for bearer authentication for the Retire JS repository URL.                            | &nbsp;                                                                                   |
 retirejs     | forceupdate   | Sets whether the Retire JS repository should update regardless of the `autoupdate` setting.             | false                                                                                    |
