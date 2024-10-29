Configuration
====================
Once dependency-check-ant has been [installed](index.html) the defined tasks can be used.

* dependency-check - the primary task used to check the project dependencies. Configuration options are below.
* dependency-check-purge - deletes the local copy of the NVD; this should rarely be used (if ever). See the [purge configuration](config-purge.html) for more information.
* dependency-check-update - downloads and updates the local copy of the NVD. See the [update configuration](config-update.html) for more information.

To configure the dependency-check task you can add it to a target and include a
file based [resource collection](http://ant.apache.org/manual/Types/resources.html#collection)
such as a [FileSet](http://ant.apache.org/manual/Types/fileset.html), [DirSet](http://ant.apache.org/manual/Types/dirset.html),
or [FileList](http://ant.apache.org/manual/Types/filelist.html) that includes
the project's dependencies.

```xml
<target name="dependency-check" description="Dependency-Check Analysis">
    <dependency-check projectname="Hello World"
                      reportoutputdirectory="${basedir}"
                      reportformat="ALL">
        <suppressionfile path="${basedir}/path/to/suppression.xml" />
        <retirejsFilter regex="copyright.*jeremy long" />
        <fileset dir="lib">
            <include name="**/*.jar"/>
        </fileset>
    </dependency-check>
</target>
```

Configuration: dependency-check Task
--------------------
The following properties can be set on the dependency-check task.

Property              | Description                                                                                                                                                                                                    | Default Value
----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------
autoUpdate            | Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to false.                                                                                             | true
failOnError           | Whether the build should fail if there is an error executing the dependency-check analysis                                                                                                                     | true
failBuildOnCVSS       | Specifies if the build should be failed if a CVSS score equal to or above a specified level is identified. The default is 11 which means since the CVSS scores are 0-10, by default the build will never fail. More information on CVSS scores can be found at the [NVD](https://nvd.nist.gov/vuln-metrics/cvss)| 11
junitFailOnCVSS       | If using the JUNIT report format the junitFailOnCVSS sets the CVSS score threshold that is considered a failure.                                                                                               | 0
prettyPrint           | Whether the XML and JSON formatted reports should be pretty printed.                                                                                                                                           | false
projectName           | The name of the project being scanned.                                                                                                                                                                         | Dependency-Check
reportFormat          | The report format to be generated (HTML, XML, CSV, JSON, JUNIT, SARIF, JENKINS, GITLAB, ALL).                                                                                                                  | HTML
reportOutputDirectory | The location to write the report(s). Note, this is not used if generating the report as part of a `mvn site` build                                                                                             | 'target'
hintsFile             | The file path to the XML hints file \- used to resolve [false negatives](../general/hints.html)                                                                                                                | &nbsp;
proxyServer           | The Proxy Server; see the [proxy configuration](../data/proxy.html) page for more information.                                                                                                                 | &nbsp;
proxyPort             | The Proxy Port.                                                                                                                                                                                                | &nbsp;
proxyUsername         | Defines the proxy user name.                                                                                                                                                                                   | &nbsp;
proxyPassword         | Defines the proxy password.                                                                                                                                                                                    | &nbsp;
nonProxyHosts         | Defines the hosts that will not be proxied.                                                                                                                                                                    | &nbsp;
connectionTimeout     | The URL Connection Timeout.                                                                                                                                                                                    | &nbsp;
enableExperimental    | Enable the [experimental analyzers](../analyzers/index.html). If not enabled the experimental analyzers (see below) will not be loaded or used.                                                                | false
enableRetired         | Enable the [retired analyzers](../analyzers/index.html). If not enabled the retired analyzers (see below) will not be loaded or used.                                                                          | false
suppressionFile       | The file path to the XML suppression file \- used to suppress [false positives](../general/suppression.html). The parameter value can be a local file path, a URL to a suppression file, or even a reference to a file on the class path (see https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799) | &nbsp;
junitFailOnCVSS       | If using the JUNIT report format the junitFailOnCVSS sets the CVSS score threshold that is considered a failure.                                                                                               | 0

The following nested elements can be set on the dependency-check task.

Element           | Property | Description                                                                                                                                                                                        | Default Value
------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------
suppressionFile   | path     | The file path to the XML suppression file \- used to suppress [false positives](../general/suppression.html). Element can be specified multiple times. The parameter value can be a local file path, a URL to a suppression file, or even a reference to a file on the class path (see https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799) | &nbsp;| &nbsp;
reportFormat      | format   | The report format to be generated (HTML, XML, CSV, JSON, JUNIT, SARIF, JENKINS, GITLAB, ALL). Element can be specified multiple times.                                                             | &nbsp;


Analyzer Configuration
====================
The following properties are used to configure the various file type analyzers.
These properties can be used to turn off specific analyzers if it is not needed.
Note, that specific analyzers will automatically disable themselves if no file
types that they support are detected - so specifically disabling them may not
be needed.

Property                            | Description                                                                                                | Default Value
------------------------------------|------------------------------------------------------------------------------------------------------------|------------------
archiveAnalyzerEnabled              | Sets whether the Archive Analyzer will be used.                                                            | true
zipExtensions                       | A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed. | &nbsp;
jarAnalyzer                         | Sets whether the Jar Analyzer will be used.                                                                | true
centralAnalyzerEnabled              | Sets whether the Central Analyzer will be used. **Disabling this analyzer for Ant builds is not recommended as it could lead to false negatives (e.g. libraries that have vulnerabilities may not be reported correctly).** If this analyzer is being disabled there is a good chance you also want to disable the Nexus Analyzer (see below).                                  | true
centralAnalyzerUseCache             | Sets whether the Central Analyer will cache results. Cached results expire after 30 days.                  | true
dartAnalyzerEnabled                 | Sets whether the [experimental](../analyzers/index.html) Dart Analyzer will be used.                       | true
knownExploitedEnabled               | Sets whether the Known Exploited Vulnerability update and analyzer are enabled.                            | true
knownExploitedUrl                   | Sets URL to the CISA Known Exploited Vulnerabilities JSON data feed.                                       | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
ossIndexAnalyzerEnabled             | Sets whether the [OSS Index Analyzer](../analyzers/oss-index-analyzer.html) will be enabled. This analyzer requires an internet connection. | true
ossindexAnalyzerUseCache            | Sets whether the OSS Index Analyzer will cache results. Cached results expire after 24 hours.              | true
ossindexAnalyzerUsername            | Sets the username for OSS Index - note an account with OSS Index is not required.                          | &nbsp;
ossindexAnalyzerPassword            | Sets the password for OSS Index.                                                                           | &nbsp;
ossIndexAnalyzerWarnOnlyOnRemoteErrors | Whether we should only warn about Sonatype OSS Index remote errors instead of failing completely.       | &nbsp;
nexusAnalyzerEnabled                | Sets whether Nexus Analyzer will be used (requires Nexus Pro). This analyzer is superceded by the Central Analyzer; however, you can configure this to run against a Nexus Pro installation. | true
nexusUrl                            | Defines the Nexus web service endpoint (example http://domain.enterprise/nexus/service/local/). If not set the Nexus Analyzer will be disabled. | &nbsp;
nexusUser                           | The username to authenticate to the Nexus Server's web service end point. If not set the Nexus Analyzer will use an unauthenticated connection. | &nbsp;
nexusPassword                       | The password to authenticate to the Nexus Server's web service end point. If not set the Nexus Analyzer will use an unauthenticated connection. | &nbsp;
nexusUsesProxy                      | Whether the defined proxy should be used when connecting to Nexus.                                  | true
artifactoryAnalyzerEnabled          | Sets whether Artifactory analyzer will be used                                                             | false
artifactoryAnalyzerUrl              | The Artifactory server URL.                                                                                | &nbsp;
artifactoryAnalyzerUseProxy         | Whether Artifactory should be accessed through a proxy or not.                                             | false
artifactoryAnalyzerParallelAnalysis | Whether the Artifactory analyzer should be run in parallel or not                                          | true
artifactoryAnalyzerUsername         | The user name (only used with API token) to connect to Artifactory instance                                | &nbsp;
artifactoryAnalyzerApiToken         | The API token to connect to Artifactory instance, only used if the username or the API key are not defined by artifactoryAnalyzerServerId,artifactoryAnalyzerUsername or artifactoryAnalyzerApiToken | &nbsp;
artifactoryAnalyzerBearerToken      | The bearer token to connect to Artifactory instance                                                        | &nbsp;
pyDistributionAnalyzerEnabled       | Sets whether the [experimental](../analyzers/index.html) Python Distribution Analyzer will be used. `enableExperimental` must be set to true. | true
pyPackageAnalyzerEnabled            | Sets whether the [experimental](../analyzers/index.html) Python Package Analyzer will be used. `enableExperimental` must be set to true. | true
rubygemsAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) Ruby Gemspec Analyzer will be used. `enableExperimental` must be set to true. | true
opensslAnalyzerEnabled              | Sets whether the openssl Analyzer should be used.                                                          | true
cmakeAnalyzerEnabled                | Sets whether the [experimental](../analyzers/index.html) CMake Analyzer should be used. `enableExperimental` must be set to true. | true
autoconfAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) autoconf Analyzer should be used. `enableExperimental` must be set to true. | true
pipAnalyzerEnabled                  | Sets whether the [experimental](../analyzers/index.html) pip Analyzer should be used. `enableExperimental` must be set to true. | true
pipfileAnalyzerEnabled              | Sets whether the [experimental](../analyzers/index.html) Pipfile Analyzer should be used. `enableExperimental` must be set to true. | true
poetryAnalyzerEnabled               | Sets whether the [experimental](../analyzers/index.html) Poetry Analyzer should be used. `enableExperimental` must be set to true. | true
composerAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) PHP Composer Lock File Analyzer should be used. `enableExperimental` must be set to true. | true
composerAnalyzerSkipDev             | Sets whether the [experimental](../analyzers/index.html) PHP Composer Lock File Analyzer should skip "packages-dev" | false
cpanfileAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) Perl CPAN File Analyzer should be used. `enableExperimental` must be set to true. | true
nodeAnalyzerEnabled                 | Sets whether the [retired](../analyzers/index.html) Node.js Analyzer should be used.                       | true
nodeAuditAnalyzerEnabled            | Sets whether the Node Audit Analyzer should be used. This analyzer requires an internet connection.        | true
nodeAuditAnalyzerUseCache           | Sets whether the Node Audit Analyzer will cache results. Cached results expire after 24 hours.             | true
nodeAuditSkipDevDependencies        | Sets whether the Node Audit Analyzer will skip devDependencies.                                            | false
nodePackageSkipDevDependencies      | Sets whether the Node Package Analyzer will skip devDependencies.                                          | false
yarnAuditAnalyzerEnabled            | Sets whether the Yarn Audit Analyzer should be used. This analyzer requires yarn and an internet connection. Use `nodeAuditSkipDevDependencies` to skip dev dependencies. | true
pnpmAuditAnalyzerEnabled            | Sets whether the Pnpm Audit Analyzer should be used. This analyzer requires pnpm and an internet connection. Use `nodeAuditSkipDevDependencies` to skip dev dependencies. | true
pathToYarn                          | The path to `yarn`.                                                                                        | &nbsp;
pathToPnpm                          | The path to `pnpm`.                                                                                        | &nbsp;
retireJsAnalyzerEnabled             | Sets whether the RetireJS Analyzer should be used.                                                         | true
retireJsForceUpdate                 | Sets whether the RetireJS Analyzer should update regardless of the `autoupdate` setting.                   | false
retirejsFilterNonVulnerable         | Configures the RetireJS Analyzer to remove non-vulnerable JS dependencies from the report.                 | false
retirejsFilter                      | A nested configuration that can be specified multple times; The regex defined is used to filter JS files based on content. | &nbsp;
retireJsUrl                         | The URL to the Retire JS repository.                                                                       | https://raw.githubusercontent.com/Retirejs/retire.js/main/repository/jsrepository.json
nuspecAnalyzerEnabled               | Sets whether the .NET Nuget Nuspec Analyzer will be used.                                                  | true
nugetconfAnalyzerEnabled            | Sets whether the [experimental](../analyzers/index.html) .NET Nuget packages.config Analyzer will be used. `enableExperimental` must be set to true. | true
libmanAnalyzerEnabled               | Sets whether the Libman Analyzer will be used.                                                             | true
cocoapodsAnalyzerEnabled            | Sets whether the [experimental](../analyzers/index.html) Cocoapods Analyzer should be used. `enableExperimental` must be set to true. | true
carthageAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) Carthage Analyzer should be used. `enableExperimental` must be set to true. | true
mixAuditAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) Mix Audit Analyzer should be used. `enableExperimental` must be set to true. | true
mixAuditPath                        | Sets the path to the mix_audit executable; only used if mix audit analyzer is enabled and experimental analyzers are enabled.  | &nbsp;
bundleAuditAnalyzerEnabled          | Sets whether the [experimental](../analyzers/index.html) Bundle Audit Analyzer should be used. `enableExperimental` must be set to true. | true
bundleAuditPath                     | Sets the path to the bundle audit executable; only used if bundle audit analyzer is enabled and experimental analyzers are enabled.  | &nbsp;
swiftPackageManagerAnalyzerEnabled  | Sets whether the [experimental](../analyzers/index.html) Swift Package Analyzer should be used. `enableExperimental` must be set to true. | true
swiftPackageResolvedAnalyzerEnabled | Sets whether the [experimental](../analyzers/index.html) Swift Package Resolved should be used. `enableExperimental` must be set to true. | true
assemblyAnalyzerEnabled             | Sets whether the .NET Assembly Analyzer should be used.                                                    | true
msbuildAnalyzerEnabled              | Sets whether the MSBuild Analyzer should be used.                                                          | true
pathToCore                          | The path to dotnet core .NET assembly analysis on non-windows systems.                                     | &nbsp;
golangDepEnabled                    | Sets whether the [experimental](../analyzers/index.html) Golang Dependency Analyzer should be used. `enableExperimental` must be set to true. | true
golangModEnabled                    | Sets whether the [experimental](../analyzers/index.html) Goland Module Analyzer should be used; requires `go` to be installed. `enableExperimental` must be set to true. | true
pathToGo                            | The path to `go`.                                                                                          | &nbsp;

Advanced Configuration
====================
The following properties can be configured in the plugin. However, they are less frequently changed.

Property             | Description                                                                                                                                                                                                                        | Default Value
---------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------
nvdApiKey            | The API Key to access the NVD API; obtained from https://nvd.nist.gov/developers/request-an-api-key                                                                                                                                | &nbsp;
nvdApiEndpoint       | The NVD API endpoint URL; setting this is uncommon.                                                                                                                                                                                | https://services.nvd.nist.gov/rest/json/cves/2.0
nvdMaxRetryCount     | The maximum number of retry requests for a single call to the NVD API.                                                                                                                                                             | 10
nvdApiDelay          | The number of milliseconds to wait between calls to the NVD API.                                                                                                                                                                   | 3500 with an NVD API Key or 8000 without an API Key
nvdApiResultsPerPage | The number records for a single page from NVD API (must be <=2000).                                                                                                                                                                | 2000
nvdDatafeedUrl       | The URL for the NVD API Data feed that can be generated using https://github.com/jeremylong/Open-Vulnerability-Project/tree/main/vulnz#caching-the-nvd-cve-data - example value `https://internal.server/cache/nvdcve-{0}.json.gz` | &nbsp;
nvdUser              | Credentials used for basic authentication for the NVD API Data feed.                                                                                                                                                               | &nbsp;
nvdPassword          | Credentials used for basic authentication for the NVD API Data feed.                                                                                                                                                               | &nbsp;
nvdValidForHours     | The number of hours to wait before checking for new updates from the NVD. The default is 4 hours.                                                                                                                                  | 4
dataDirectory        | Data directory that is used to store the local copy of the NVD. This should generally not be changed.                                                                                                                              | data
databaseDriverName   | The database driver full classname; note, only needs to be set if the driver is not JDBC4 compliant or the JAR is outside of the class path.                                                                                       | &nbsp;
databaseDriverPath   | The path to the database driver JAR file; only needs to be set if the driver is not in the class path.                                                                                                                             | &nbsp;
connectionString     | The connection string used to connect to the database. See using a [database server](../data/database.html).                                                                                                                       | &nbsp;
databaseUser         | The username used when connecting to the database.                                                                                                                                                                                 | &nbsp;
databasePassword     | The password used when connecting to the database.                                                                                                                                                                                 | &nbsp;
hostedSuppressionsEnabled | Whether the hosted suppression file will be used.                                                                                                                                                                                  | true
hostedSuppressionsUrl | The URL to a mirrored copy of the hosted suppressions file for internet-constrained environments                                                                                                                                   | https://jeremylong.github.io/DependencyCheck/suppressions/publishedSuppressions.xml
hostedSuppressionsValidForHours | Sets the number of hours to wait before checking for new updates of the hosted suppressions file                                                                                                                                   | 2
hostedSuppressionsForceUpdate | Sets whether the hosted suppressions file should update regardless of the `autoupdate` and validForHours settings                                                                                                                  | false