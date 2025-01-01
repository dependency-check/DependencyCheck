Tasks
====================

Task                                                     | Description
---------------------------------------------------------|-----------------------
dependencyCheckAnalyze                                   | Runs dependency-check against the project and generates a report.
[dependencyCheckAggregate](configuration-aggregate.html) | Runs dependency-check against a multi-project build and generates a report.
[dependencyCheckUpdate](configuration-update.html)       | Updates the local cache of the NVD data from NIST.
[dependencyCheckPurge](configuration-purge.html)         | Deletes the local copy of the NVD. This is used to force a refresh of the data.

Configuration:
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

check.dependsOn dependencyCheckAnalyze
```

Property             | Description                                                                                                          | Default Value
---------------------|----------------------------------------------------------------------------------------------------------------------|------------------
autoUpdate           | Sets whether auto-updating of the NVD API CVE data is enabled. It is not recommended that this be turned to false.   | true
analyzedTypes        | The default artifact types that will be analyzed.                                                                    | ['jar', 'aar', 'js', 'war', 'ear', 'zip']
format               | The report format to be generated (HTML, XML, CSV, JSON, JUNIT, SARIF, JENKINS, GITLAB, ALL).                        | HTML
formats              | A list of report formats to be generated (HTML, XML, CSV, JSON, JUNIT, SARIF, JENKINS, GITLAB, ALL).                 | &nbsp;
junitFailOnCVSS      | If using the JUNIT report format the junitFailOnCVSS sets the CVSS score threshold that is considered a failure.     | 0
failBuildOnCVSS      | Specifies if the build should be failed if a CVSS score equal to or above a specified level is identified. The default is 11; since the CVSS scores are 0-10, by default the build will never fail. More information on CVSS scores can be found at the [NVD](https://nvd.nist.gov/vuln-metrics/cvss) | 11
failOnError          | Fails the build if an error occurs during the dependency-check analysis.                                             | true
outputDirectory      | The location to write the report(s). This directory will be located in the build directory.                          | ${buildDir}/reports
skipTestGroups       | When set to true (the default) all dependency groups that being with 'test' will be skipped.                         | true
suppressionFile      | The file path to the XML suppression file \- used to suppress [false positives](../general/suppression.html). The configured value can be a local file path, a URL to a suppression file, or even a reference to a file on the class path (see https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799) | &nbsp;
suppressionFiles     | A list of file paths to the XML suppression files \- used to suppress [false positives](../general/suppression.html). The configured values can be a local file path, a URL to a suppression file, or even a reference to a file on the class path (see https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799) | &nbsp;
hintsFile            | The file path to the XML hints file \- used to resolve [false negatives](../general/hints.html)                      | &nbsp;
skip                 | If set to true dependency-check analysis will be skipped.                                                            | false
skipConfigurations   | A list of configurations that will be skipped. This is mutually exclusive with the scanConfigurations property.      | `[]` which means no configuration is skipped.
scanConfigurations   | A list of configurations that will be scanned, all other configurations are skipped. This is mutually exclusive with the skipConfigurations property. | `[]` which implicitly means all configurations get scanned.
scanProjects         | A list of projects that will be scanned, all other projects are skipped. The list or projects to skip must include a preceding colon: `scanProjects = [':app']`. This is mutually exclusive with the `skipProjects` property. | `[]` which implicitly means all projects get scanned.
skipProjects         | A list of projects that will be skipped.  The list or projects to skip must include a preceding colon: `skipProjects = [':sub1']`. This is mutually exclusive with the `scanProjects` property. | `[]` which means no projects are skipped.
scanBuildEnv         | A boolean indicating whether to scan the `buildEnv`.                                                                 | false
scanDependencies     | A boolean indicating whether to scan the `dependencies`.                                                             | true
scanSet              | A list of directories that will be scanned for additional dependencies.                                              | ['src/main/resources','src/main/webapp']

#### Example
```groovy
dependencyCheck {
    autoUpdate=false
    format='ALL'
}
```

### Proxy Configuration

Please see https://docs.gradle.org/current/userguide/build_environment.html#sec:accessing_the_web_via_a_proxy

### Advanced Configuration

The following properties can be configured in the dependencyCheck task. However, they are less frequently changed.

Config Group | Property          | Description                                                                                                                                                     | Default Value
-------------|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------
&nbsp;       | suppressionFileUser        | Credentials used for basic authentication for web-hosted suppression files                                                                             | &nbsp; |
&nbsp;       | suppressionFilePassword    | Credentials used for basic authentication for web-hosted suppression files                                                                             | &nbsp; |
&nbsp;       | suppressionFileBearerToken | Credentials used for bearer authentication for web-hosted suppression files                                                                            | &nbsp; |
nvd          | apiKey            | The API Key to access the NVD API; obtained from https://nvd.nist.gov/developers/request-an-api-key                                                             | &nbsp;                                                              |
nvd          | endpoint          | The NVD API endpoint URL; setting this is uncommon.                                                                                                             | https://services.nvd.nist.gov/rest/json/cves/2.0                            |
nvd          | maxRetryCount     | The maximum number of retry requests for a single call to the NVD API.                                                                                          | 10                                                                  |
nvd          | delay             | The number of milliseconds to wait between calls to the NVD API.                                                                                                | 3500 with an NVD API Key or 8000 without an API Key                 |
nvd          | resultsPerPage    | The number records for a single page from NVD API (must be <=2000).                                                                                             | 2000                                                                |
nvd          | datafeedUrl       | The URL for the NVD API Data feed that can be generated using https://github.com/jeremylong/Open-Vulnerability-Project/tree/main/vulnz#caching-the-nvd-cve-data | &nbsp;                   |
nvd          | datafeedUser      | Credentials used for basic authentication for the NVD API Data feed.                                                                                            | &nbsp;                                                              |
nvd          | datafeedPassword  | Credentials used for basic authentication for the NVD API Data feed.                                                                                            | &nbsp;                                                              |
nvd          | datafeedBearerToken  | Credentials used for bearer authentication for the NVD API Data feed.                                                                                        | &nbsp;                                                              |
nvd          | validForHours     | The number of hours to wait before checking for new updates from the NVD. The default is 4 hours.                                                               | 4                                                                   |
data         | directory         | Sets the data directory to hold SQL CVEs contents. This should generally not be changed.                                                                        | &nbsp;                                                              |
data         | driver            | The database driver full classname; note, only needs to be set if the driver is not JDBC4 compliant or the JAR is outside of the class path.                    | &nbsp;                                                              |
data         | driverPath        | The path to the database driver JAR file; only needs to be set if the driver is not in the class path.                                                          | &nbsp;                                                              |
data         | connectionString  | The connection string used to connect to the database. See using a [database server](../data/database.html).                                                    | &nbsp;                                                              |
data         | username          | The username used when connecting to the database.                                                                                                              | &nbsp;                                                              |
data         | password          | The password used when connecting to the database.                                                                                                              | &nbsp;                                                              |
slack        | enabled               | Whether or not slack notifications are enabled.                                                                   | false
slack        | webhookUrl            | The custom incoming webhook URL to receive notifications.                                                         | &nbsp;
hostedSuppressions | enabled         | Whether the hosted suppressions file will be used.                                                                | true
hostedSuppressions | forceupdate     | Sets whether hosted suppressions file will update regardless of the `autoupdate` setting.                         | false
hostedSuppressions | url             | The URL to a mirrored copy of the hosted suppressions file for internet-constrained environments.                 | https://jeremylong.github.io/DependencyCheck/suppressions/publishedSuppressions.xml
hostedSuppressions | user            | Credentials used for basic authentication for the hosted suppressions file.                                                                                     | &nbsp;                                                              |
hostedSuppressions | password        | Credentials used for basic authentication for the hosted suppressions file.                                                                                     | &nbsp;                                                              |
hostedSuppressions | bearerToken     | Credentials used for bearer authentication for the hosted suppressions file.                                                                                    | &nbsp;                                                              |
hostedSuppressions | validForHours   | The number of hours to wait before checking for new updates of the hosted suppressions file .                     | 2

#### Example
```groovy
dependencyCheck {
    data.directory='d:/nvd'
}
```

### Analyzer Configuration

In addition to the above, the dependencyCheck plugin can be configured to enable or disable specific
analyzers by configuring the `analyzers` section. Note, specific file type analyzers will automatically
disable themselves if no file types that they support are detected - so specifically disabling the
analyzers is likely not needed.

Config Group | Property              | Description                                                                                                       | Default Value
-------------|-----------------------|-------------------------------------------------------------------------------------------------------------------|------------------
analyzers    | experimentalEnabled   | Sets whether the [experimental analyzers](../analyzers/index.html) will be used. If not set to true the analyzers marked as experimental (see below) will not be used | false
analyzers    | archiveEnabled        | Sets whether the Archive Analyzer will be used.                                                                   | true
analyzers    | zipExtensions         | A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed. | &nbsp;
analyzers    | jarEnabled            | Sets whether Jar Analyzer will be used.                                                                           | true
analyzers    | dartEnabled           | Sets whether the [experimental](../analyzers/index.html) Dart Analyzer will be used.                              | true
analyzers    | centralEnabled        | Sets whether Central Analyzer will be used; by default in the Gradle plugin this analyzer is disabled as all information gained from Central is already available in the build. Enable this analyzer when you hit false positives for (embedded) Maven dependencies that do not have an associated maven package-URL in the report. | false
analyzers    | nexusEnabled          | Sets whether Nexus Analyzer will be used (requires Nexus Pro). This analyzer is superceded by the Central Analyzer; however, you can configure this to run against a Nexus Pro installation. | false
analyzers    | nexusUrl              | Defines the Nexus Server's web service end point (example http://domain.enterprise/service/local/). If not set the Nexus Analyzer will be disabled. | &nbsp;
analyzers    | nexusUsesProxy        | Whether or not the defined proxy should be used when connecting to Nexus.                                         | true
analyzers    | pyDistributionEnabled | Sets whether the [experimental](../analyzers/index.html) Python Distribution Analyzer will be used. `experimentalEnabled` must be set to true. | true
analyzers    | pyPackageEnabled      | Sets whether the [experimental](../analyzers/index.html) Python Package Analyzer will be used. `experimentalEnabled` must be set to true. | true
analyzers    | rubygemsEnabled       | Sets whether the [experimental](../analyzers/index.html) Ruby Gemspec Analyzer will be used. `experimentalEnabled` must be set to true. | true
analyzers    | opensslEnabled        | Sets whether the openssl Analyzer should be used.                                                          | true
analyzers    | nuspecEnabled         | Sets whether the .NET Nuget Nuspec Analyzer will be used.                                                  | true
analyzers    | nugetconfEnabled      | Sets whether the [experimental](../analyzers/index.html) .NET Nuget packages.config Analyzer will be used. `experimentalEnabled` must be set to true. | true
analyzers    | assemblyEnabled       | Sets whether the .NET Assembly Analyzer should be used.                                                    | true
analyzers    | msbuildEnabled        | Sets whether the MS Build Analyzer should be used.                                                         | true
analyzers    | pathToDotnet          | The path to dotnet core - needed on some systems to analyze .net assemblies.                                      | &nbsp;
analyzers    | cmakeEnabled          | Sets whether the [experimental](../analyzers/index.html) CMake Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | autoconfEnabled       | Sets whether the [experimental](../analyzers/index.html) autoconf Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | composerEnabled       | Sets whether the [experimental](../analyzers/index.html) PHP Composer Lock File Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | composerSkipDev       | Sets whether the [experimental](../analyzers/index.html) PHP Composer Lock File Analyzer should skip "packages-dev". | false
analyzers    | cpanEnabled           | Sets whether the [experimental](../analyzers/index.html) Perl CPAN File Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | cocoapodsEnabled      | Sets whether the [experimental](../analyzers/index.html) Cocoapods Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | carthageEnabled       | Sets whether the [experimental](../analyzers/index.html) Carthage Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | swiftEnabled          | Sets whether the [experimental](../analyzers/index.html) Swift Package Manager Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | swiftPackageResolvedEnabled | Sets whether the [experimental](../analyzers/index.html) Swift Package Resolved Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | bundleAuditEnabled    | Sets whether the [experimental](../analyzers/index.html) Ruby Bundle Audit Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | pathToBundleAudit     | The path to bundle audit.                                                                                         | &nbsp;
analyzers    | retiredEnabled        | Sets whether the [retired analyzers](../analyzers/index.html) will be used. If not set to true the analyzers marked as experimental (see below) will not be used | false
analyzers    | golangDepEnabled      | Sets whether the [experimental](../analyzers/index.html) Golang Dependency Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | golangModEnabled      | Sets whether the [experimental](../analyzers/index.html) Goland Module Analyzer should be used; requires `go` to be installed. `experimentalEnabled` must be set to true. | true
analyzers    | pathToGo              | The path to `go`.                                                                                                 | &nbsp;

#### Additional Configuration

Config Group | Property              | Description                                                                                                       | Default Value
-------------|-----------------------|-------------------------------------------------------------------------------------------------------------------|------------------
artifactory  | enabled               | Sets whether Artifactory analyzer will be used                                                                    | false
artifactory  | url                   | The Artifactory server URL.                                                                                       | &nbsp;
artifactory  | usesProxy             | Whether Artifactory should be accessed through a proxy or not.                                                    | false
artifactory  | parallelAnalysis      | Whether the Artifactory analyzer should be run in parallel or not.                                                | true
artifactory  | username              | The user name (only used with API token) to connect to Artifactory instance.                                      | &nbsp;
artifactory  | apiToken              | The API token to connect to Artifactory instance, only used if the username or the API key are not defined by artifactoryAnalyzerServerId,artifactoryAnalyzerUsername or artifactoryAnalyzerApiToken | &nbsp;
artifactory  | bearerToken           | The bearer token to connect to Artifactory instance                                                               | &nbsp;
kev          | enabled               | Sets whether the Known Exploited Vulnerability update and analyzer are enabled.                                   | true                                                                                     |
kev          | url                   | The URL to (a mirror of) the CISA Known Exploited Vulnerabilities JSON data feed.                                 | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json      |
kev          | user                  | Credentials used for basic authentication for the CISA Known Exploited Vulnerabilities JSON data feed.            | &nbsp;                                                                                   |
kev          | password              | Credentials used for basic authentication for the CISA Known Exploited Vulnerabilities JSON data feed.            | &nbsp;                                                                                   |
kev          | bearerToken           | Credentials used for bearer authentication for the CISA Known Exploited Vulnerabilities JSON data feed.           | &nbsp;                                                                                   |
kev          | validForHours         | The number of hours to wait before checking for new updates of the hosted suppressions file .                     | 2                                                                                        |
nodeAudit    | enabled               | Sets whether the Node Audit Analyzer should be used. This analyzer requires an internet connection.               | true
nodeAudit    | useCache              | Sets whether the Node Audit Analyzer should cache results locally.                                                | true
nodeAudit    | skipDevDependencies   | Sets whether the Node Audit Analyzer should skip devDependencies.                                                 | false
nodeAudit    | pnpmEnabled           | Sets whether the Pnpm Audit Analyzer should be used. This analyzer requires yarn and an internet connection.      | true
nodeAudit    | pnpmPath              | Sets the path to the `pnpm` executable.                                                                           | &nbsp;
nodeAudit    | yarnEnabled           | Sets whether the Yarn Audit Analyzer should be used. This analyzer requires yarn and an internet connection.      | true
nodeAudit    | yarnPath              | Sets the path to the `yarn` executable.                                                                           | &nbsp;
nodeAudit    | pnpmEnabled           | Sets whether the Pnpm Audit Analyzer should be used. This analyzer requires pnpm and an internet connection.      | true
nodeAudit    | pnpmPath              | The path to `pnpm`.                                                                                               | &nbsp;
nodeAudit    | url                   | The node audit API url to use.                                                                                    | &nbsp;
retirejs     | enabled               | Sets whether the RetireJS Analyzer should be used.                                                                | true
retirejs     | forceupdate           | Sets whether the RetireJS Analyzer should update regardless of the `autoupdate` setting.                          | false
retirejs     | retireJsUrl           | The URL to the Retire JS repository.                                                                              | https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json
retirejs     | user                  | Credentials used for basic authentication for the Retire JS repository URL.                                       | &nbsp;                                                                                   |
retirejs     | password              | Credentials used for basic authentication for the Retire JS repository URL.                                       | &nbsp;                                                                                   |
retirejs     | bearerToken           | Credentials used for bearer authentication for the Retire JS repository URL.                                      | &nbsp;                                                                                   |
retirejs     | filterNonVulnerable   | Configures the RetireJS Analyzer to remove non-vulnerable JS dependencies from the report.                        | false
retirejs     | filters               | Configures the list of regular expessions used to filter JS files based on content.                               | &nbsp;
ossIndex     | enabled               | Sets whether Sonatype's [OSS Index Analyzer](../analyzers/oss-index-analyzer.html) will be used. This analyzer requires an internet connection.                                                                  | true
ossIndex     | username              | The optional user name to connect to Sonatype's OSS Index.                                                        | &nbsp;
ossIndex     | password              | The optional passwod or API token to connect to Sonatype's OSS Index,                                             | &nbsp;
ossIndex     | warnOnlyOnRemoteErrors| Sets whether remote errors from the OSS Index (e.g. BAD GATEWAY, RATE LIMIT EXCEEDED) will result in warnings only instead of failing execution. | false

#### Example
```groovy
dependencyCheck {
    analyzers {
        assemblyEnabled=false
        artifactory {
            enabled=true
            url='https://internal.artifactory.url'
        }
        retirejs {
            filters = ['(i)copyright Jeremy Long']
        }
        ossIndex {
            username = 'example@gmail.com'
            password = '42cc601cd7ff12a531a0b1eada8dcf56d777b336'
    }
}
```
