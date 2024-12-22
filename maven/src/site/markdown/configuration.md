Goals
====================

Goal        | Description
------------|-----------------------
aggregate   | Runs dependency-check against the child projects and aggregates the results into a single report. **Warning**: if the aggregate goal is used within the site reporting a blank report will likely be present for any goal beyond site:site (i.e. site:stage or site:deploy will likely result in blank reports being staged or deployed); however, site:site will work. See issue [#325](https://github.com/jeremylong/DependencyCheck/issues/325) for more information.
check       | Runs dependency-check against the project and generates a report.
update-only | Updates the local cache of the NVD data from NIST.
purge       | Deletes the local copy of the NVD. This is used to force a refresh of the data.

Configuration
====================
The following properties can be set on the dependency-check-maven plugin.

Property                         | Description                        | Default Value
---------------------------------|------------------------------------|------------------
autoUpdate                       | Sets whether auto-updating of the NVD CVE/CPE, retireJS and hosted suppressions data is enabled. It is not recommended that this be turned to false. | true
format                           | The report format to be generated (HTML, XML, CSV, JSON, JUNIT, SARIF, JENKINS, GITLAB, ALL). This configuration is ignored if `formats` is defined. This configuration option has no affect if using this within the Site plugin unless the externalReport is set to true. | HTML
formats                          | A list of report formats to be generated (HTML, XML, CSV, JSON, JUNIT, SARIF, JENKINS, GITLAB, ALL). This configuration overrides the value from `format`. This configuration option has no affect if using this within the Site plugin unless the externalReport is set to true. | &nbsp;
junitFailOnCVSS                  | If using the JUNIT report format the junitFailOnCVSS sets the CVSS score threshold that is considered a failure.   | 0
prettyPrint                      | Whether the XML and JSON formatted reports should be pretty printed.                                               | false
failBuildOnCVSS                  | Specifies if the build should be failed if a CVSS score equal to or above a specified level is identified. The default is 11 which means since the CVSS scores are 0-10, by default the build will never fail. More information on CVSS scores can be found at the [NVD](https://nvd.nist.gov/vuln-metrics/cvss) | 11
failBuildOnAnyVulnerability      | Specifies that if any vulnerability is identified, the build will fail. | false
failOnError                      | Whether the build should fail if there is an error executing the dependency-check analysis. | true
name                             | The name of the report in the site. | dependency-check or dependency-check:aggregate
outputDirectory                  | The location to write the report(s). This can be specified on the command line via `-Dodc.outputDirectory`. Note, this is not used if generating the report as part of a `mvn site` build. | 'target'
scanSet                          | An optional collection of file sets that specify additional files and/or directories to analyze as part of the scan. If not specified, defaults to standard Maven conventions. This cannot be configured via the command line parameters (e.g. `-DscanSet=./path`) - use the below `scanDirectory` instead. Note that the scan sets specified should be relative from the base directory - do not use Maven project variable substitution (e.g. `${project.basedir}/src/webpack`). Using Maven project variable substitution can cause directories to be missed especially when using an aggregate build. | ['src/main/resources', 'src/main/filters', 'src/main/webapp', './package.json', './package-lock.json', './npm-shrinkwrap.json', './Gopkg.lock', './go.mod']
scanDirectory                    | An optional collection of directories to include in the scan. This configuration should only be used via the command line - if configuring the scan directories within the `pom.xml` please consider using the above `scanSet`. | &nbsp;
scanDependencies                 | Sets whether the dependencies should be scanned.                   | true
scanPlugins                      | Sets whether the plugins and their dependencies should be scanned. | false
skip                             | Skips the dependency-check analysis.                       | false
skipProvidedScope                | Skip analysis for artifacts with Provided Scope.           | false
skipRuntimeScope                 | Skip analysis for artifacts with Runtime Scope.            | false
skipSystemScope                  | Skip analysis for artifacts with System Scope.             | false
skipTestScope                    | Skip analysis for artifacts with Test Scope.               | true
skipDependencyManagement         | Skip analysis for dependencyManagement sections.           | true
skipArtifactType                 | A regular expression used to filter/skip artifact types.  This filters on the `type` of dependency as defined in the dependency section: jar, pom, test-jar, etc. | &nbsp;
suppressionFiles                 | The file paths to the XML suppression files \- used to suppress [false positives](../general/suppression.html). The configuration value can be a local file path, a URL to a suppression file, or even a reference to a file on the class path (see https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799) | &nbsp;
hintsFile                        | The file path to the XML hints file \- used to resolve [false negatives](../general/hints.html).       | &nbsp;
enableExperimental               | Enable the [experimental analyzers](../analyzers/index.html). If not enabled the experimental analyzers (see below) will not be loaded or used. | false
enableRetired                    | Enable the [retired analyzers](../analyzers/index.html). If not enabled the retired analyzers (see below) will not be loaded or used. | false
versionCheckEnabled              | Whether dependency-check should check if a new version of dependency-check-maven exists. | true
failBuildOnUnusedSuppressionRule | Specifies that if any unused suppression rule is found, the build will fail. | false

Analyzer Configuration
====================
The following properties are used to configure the various file type analyzers.
These properties can be used to turn off specific analyzers if it is not needed.
Note, that specific analyzers will automatically disable themselves if no file
types that they support are detected - so specifically disabling them may not
be needed.

Property                            | Description                                                                                                                                         | Default Value
------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|------------------
archiveAnalyzerEnabled              | Sets whether the Archive Analyzer will be used.                                                                                                     | true
zipExtensions                       | A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed.                    | &nbsp;
excludes                            | A list of exclude patterns to filter out maven artifacts from being scanned.                                                                        | &nbsp;
jarAnalyzerEnabled                  | Sets whether Jar Analyzer will be used.                                                                                                             | true
centralAnalyzerEnabled              | Sets whether Central Analyzer will be used; by default in the Maven plugin this analyzer is disabled as all information gained from Central is already available in the build. | false
centralAnalyzerUseCache             | Sets whether the Central Analyer will cache results. Cached results expire after 30 days.                                                           | true
dartAnalyzerEnabled                 | Sets whether the [experimental](../analyzers/index.html) Dart Analyzer will be used.                                                                | true
knownExploitedEnabled               | Sets whether the Known Exploited Vulnerability update and analyzer are enabled.                                                                     | true
knownExploitedUrl                   | Sets URL to the CISA Known Exploited Vulnerabilities JSON data feed.                                                                                | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
ossindexAnalyzerEnabled             | Sets whether the [OSS Index Analyzer](../analyzers/oss-index-analyzer.html) will be enabled. This analyzer requires an internet connection.         | true
ossindexAnalyzerUseCache            | Sets whether the OSS Index Analyzer will cache results. Cached results expire after 24 hours.                                                       | true
ossindexServerId                    | The id of [a server](https://maven.apache.org/settings.html#Servers) defined in the `settings.xml` to authenticate Sonatype OSS Index requests and profit from higher rate limits. Provide the OSS account email address as `username` and password or API token as `password`. | &nbsp;
ossindexAnalyzerUrl                 | The OSS Index server URL | https://ossindex.sonatype.org
ossIndexWarnOnlyOnRemoteErrors      | Sets whether remote errors from the OSS Index (e.g. BAD GATEWAY, RATE LIMIT EXCEEDED) will result in warnings only instead of failing execution.    | false
nexusAnalyzerEnabled                | Sets whether Nexus Analyzer will be used (requires Nexus Pro). This analyzer is superceded by the Central Analyzer; however, you can configure this to run against a Nexus Pro installation. | true
nexusUrl                            | Defines the Nexus Server's web service end point (example http://domain.enterprise/service/local/). If not set the Nexus Analyzer will be disabled. | &nbsp;
nexusServerId                       | The id of a server defined in the settings.xml that configures the credentials (username and password) for a Nexus server's REST API end point. When not specified the communication with the Nexus server's REST API will be unauthenticated. | &nbsp;
nexusUsesProxy                      | Whether or not the defined proxy should be used when connecting to Nexus.                                                                           | true
artifactoryAnalyzerEnabled          | Sets whether Artifactory analyzer will be used                                                                                                      | false
artifactoryAnalyzerUrl              | The Artifactory server URL.                                                                                                                         | &nbsp;
artifactoryAnalyzerUseProxy         | Whether Artifactory should be accessed through a proxy or not.                                                                                      | false
artifactoryAnalyzerParallelAnalysis | Whether the Artifactory analyzer should be run in parallel or not                                                                                   | true
artifactoryAnalyzerServerId         | The id of a server defined in the settings.xml to retrieve the credentials (username and API token) to connect to Artifactory instance. It is used in priority to artifactoryAnalyzerUsername and artifactoryAnalyzerApiToken | artifactory
artifactoryAnalyzerUsername         | The user name (only used with API token) to connect to Artifactory instance                                                                         | &nbsp;
artifactoryAnalyzerApiToken         | The API token to connect to Artifactory instance, only used if the username or the API key are not defined by artifactoryAnalyzerServerId,artifactoryAnalyzerUsername or artifactoryAnalyzerApiToken | &nbsp;
artifactoryAnalyzerBearerToken      | The bearer token to connect to Artifactory instance                                                                                                 | &nbsp;
pyDistributionAnalyzerEnabled       | Sets whether the [experimental](../analyzers/index.html) Python Distribution Analyzer will be used. `enableExperimental` must be set to true.       | true
pyPackageAnalyzerEnabled            | Sets whether the [experimental](../analyzers/index.html) Python Package Analyzer will be used. `enableExperimental` must be set to true.            | true
rubygemsAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) Ruby Gemspec Analyzer will be used. `enableExperimental` must be set to true.              | true
opensslAnalyzerEnabled              | Sets whether the openssl Analyzer should be used.                                                                                                   | true
cmakeAnalyzerEnabled                | Sets whether the [experimental](../analyzers/index.html) CMake Analyzer should be used. `enableExperimental` must be set to true.                   | true
autoconfAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) autoconf Analyzer should be used. `enableExperimental` must be set to true.                | true
pipAnalyzerEnabled                  | Sets whether the [experimental](../analyzers/index.html) pip Analyzer should be used. `enableExperimental` must be set to true.                     | true
pipfileAnalyzerEnabled              | Sets whether the [experimental](../analyzers/index.html) Pipfile Analyzer should be used. `enableExperimental` must be set to true.                 | true
poetryAnalyzerEnabled               | Sets whether the [experimental](../analyzers/index.html) Poetry Analyzer should be used. `enableExperimental` must be set to true.                  | true
composerAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) PHP Composer Lock File Analyzer should be used. `enableExperimental` must be set to true.  | true
composerAnalyzerSkipDev             | Sets whether the [experimental](../analyzers/index.html) PHP Composer Lock File Analyzer should skip "packages-dev"                                 | false
cpanfileAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) Perl CPAN File Analyzer should be used. `enableExperimental` must be set to true.          | true
yarnAuditAnalyzerEnabled            | Sets whether the Yarn Audit Analyzer should be used. This analyzer requires yarn and an internet connection.  Use `nodeAuditSkipDevDependencies` to skip dev dependencies. | true
pnpmAuditAnalyzerEnabled            | Sets whether the Pnpm Audit Analyzer should be used. This analyzer requires pnpm and an internet connection.  Use `nodeAuditSkipDevDependencies` to skip dev dependencies. | true
pathToYarn                          | The path to `yarn`.                                                                                                                                 | &nbsp;
pathToPnpm                          | The path to `pnpm`.                                                                                                                                 | &nbsp;
nodeAnalyzerEnabled                 | Sets whether the [retired](../analyzers/index.html) Node.js Analyzer should be used.                                                                | true
nodeAuditAnalyzerEnabled            | Sets whether the Node Audit Analyzer should be used. This analyzer requires an internet connection.                                                 | true
nodeAuditAnalyzerUseCache           | Sets whether the Node Audit Analyzer will cache results. Cached results expire after 24 hours.                                                      | true
nodeAuditSkipDevDependencies        | Sets whether the Node Audit Analyzer will skip devDependencies.                                                                                     | false
nodeAuditAnalyzerUrl                | The Node Audit API URL for the Node Audit Analyzer.                                                                                                 | https://registry.npmjs.org/-/npm/v1/security/audits
nodePackageSkipDevDependencies      | Sets whether the Node Package Analyzer will skip devDependencies.                                                                                   | false
retireJsAnalyzerEnabled             | Sets whether the RetireJS Analyzer should be used.                                                                                                  | true
retireJsForceUpdate                 | Sets whether the RetireJS Analyzer should update regardless of the `autoupdate` setting.                                                            | false
retireJsUrl                         | The URL to the Retire JS repository. **Note** the file name must be `jsrepository.json`.                                                            | https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json
nuspecAnalyzerEnabled               | Sets whether the .NET Nuget Nuspec Analyzer will be used.                                                                                           | true
nugetconfAnalyzerEnabled            | Sets whether the [experimental](../analyzers/index.html) .NET Nuget packages.config Analyzer will be used. `enableExperimental` must be set to true. | true
libmanAnalyzerEnabled               | Sets whether the Libman Analyzer will be used.                                                                                                      | true
cocoapodsAnalyzerEnabled            | Sets whether the [experimental](../analyzers/index.html) Cocoapods Analyzer should be used. `enableExperimental` must be set to true.               | true
carthageAnalyzerEnabled             | Sets whether the [experimental](../analyzers/index.html) Carthage Analyzer should be used. `enableExperimental` must be set to true.                | true
bundleAuditAnalyzerEnabled          | Sets whether the [experimental](../analyzers/index.html) Bundle Audit Analyzer should be used. `enableExperimental` must be set to true.            | true
bundleAuditPath                     | Sets the path to the bundle audit executable; only used if bundle audit analyzer is enabled and experimental analyzers are enabled.                 | &nbsp;
swiftPackageManagerAnalyzerEnabled  | Sets whether the [experimental](../analyzers/index.html) Swift Package Analyzer should be used. `enableExperimental` must be set to true.           | true
swiftPackageResolvedAnalyzerEnabled | Sets whether the [experimental](../analyzers/index.html) Swift Package Resolved should be used. `enableExperimental` must be set to true.           | true
assemblyAnalyzerEnabled             | Sets whether the .NET Assembly Analyzer should be used.                                                                                             | true
msbuildAnalyzerEnabled              | Sets whether the MSBuild Analyzer should be used.                                                                                                   | true
pathToCore                          | The path to dotnet core .NET assembly analysis on non-windows systems.                                                                              | &nbsp;
golangDepEnabled                    | Sets whether or not the [experimental](../analyzers/index.html) Golang Dependency Analyzer should be used. `enableExperimental` must be set to true.| true
golangModEnabled                    | Sets whether or not the [experimental](../analyzers/index.html) Goland Module Analyzer should be used; requires `go` to be installed. `enableExperimental` must be set to true. | true
pathToGo                            | The path to `go`.                                                                                                                                   | &nbsp;

RetireJS Configuration
====================
If using the [experimental](../analyzers/index.html) RetireJS Analyzer the following configuration options are available
to control the included JS files

###Example
<pre>
    &lt;retirejs&gt;
        &lt;filters&gt;
            &lt;filter&gt;Copyright\(c\) Jeremy Long&lt;/filter&gt;
        &lt;/filters&gt;
        &lt;filterNonVulnerable&gt;true&lt;/filterNonVulnerable&gt;
    &lt;/retirejs&gt;
</pre>

Property            | Description                                                                                                                                                                                                            | Default Value
--------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------
filters             | A list of file content filters used to exclude JS files based on content. This is most commonly used to exclude JS files based on your organizations copyright so that your JS files do not get listed as a dependency.| &nbsp;
filterNonVulnerable | A boolean controlling whether or not the Retire JS Analyzer should exclude non-vulnerable JS files from the report.                                                                                                    | false

Advanced Configuration
====================
The following properties can be configured in the plugin. However, they are less frequently changed.

Note that any passwords in the below configuration could be exposed if you use `-x` option to debug the build. It is always better to configure the credential in your settings.xml and use the configuration to set the server id instead of placeing the password directly in the pom.xml.

Property                 | Description                                                                                                                                                                                                                                                                                                       | Default Value                                                       |
-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------|
nvdApiKey                | The API Key to access the NVD API; obtained from https://nvd.nist.gov/developers/request-an-api-key; The `nvdApiServerId` configuration should be used instead to store the secret securely. If the secret is placed directly in the configuration and you use -X the secret will be written to the standard out. | &nbsp; |
nvdApiEndpoint           | The NVD API endpoint URL; setting this is uncommon.                                                                                                                                                                                                                                                               | https://services.nvd.nist.gov/rest/json/cves/2.0                    |
nvdApiServerId           | The id of a server defined in the settings.xml that configures the credentials (password is used as ApiKey) for accessing the NVD API.                                                                                                                                                                            | &nbsp;                                                              |
nvdMaxRetryCount         | The maximum number of retry requests for a single call to the NVD API.                                                                                                                                                                                                                                            | 10                                                                  |
nvdApiDelay              | The number of milliseconds to wait between calls to the NVD API.                                                                                                                                                                                                                                                  | 3500 with an NVD API Key or 8000 without an API Key .               |
nvdApiResultsPerPage     | The number records for a single page from NVD API (must be <=2000).                                                                                                                                                                                                                                               | 2000                                                                |
nvdDatafeedUrl           | The URL for the NVD API Data feed that can be generated using https://github.com/jeremylong/Open-Vulnerability-Project/tree/main/vulnz#caching-the-nvd-cve-data - example value `https://internal.server/cache/nvdcve-{0}.json.gz`                                                                                | &nbsp;                                         |
nvdDatafeedServerId      | The id of a server defined in the settings.xml that configures the credentials (username and password) for accessing the NVD API Data feed.                                                                                                                                                                       | &nbsp;                                                              |
nvdUser                  | Credentials used for basic authentication for the NVD API Data feed.                                                                                                                                                                                                                                              | &nbsp;                                                              |
nvdPassword              | Credentials used for basic authentication for the NVD API Data feed. The `nvdDatafeedServerId` configuration should be used instead to store the secret securely. If the secret is placed directly in the configuration and you use -X the secret will be written to the standard out.                            | &nbsp; |
nvdValidForHours         | The number of hours to wait before checking for new updates from the NVD. The default is 4 hours.                                                                                                                                                                                                                 | 4                                                                   |
suppressionFileServerId  | The id of a server defined in the settings.xml that configures the credentials (username and password) for accessing the suppressionFiles.                                                                                                                                                                        | &nbsp;                                                              |
suppressionFileUser      | The username used when connecting to the suppressionFiles. Must be empty if suppressionFileServerId is specified and should be used.                                                                                                                                                                              | &nbsp;                                                              |
suppressionFilePassword  | The password used when connecting to the suppressionFiles. Must be empty if suppressionFileServerId is specified and should be used.                                                                                                                                                                              | &nbsp;                                                              |
connectionTimeout        | Sets the URL Connection Timeout (in milliseconds) used when downloading external data.                                                                                                                                                                                                                            | 10000                                                               |
readTimeout              | Sets the URL Read Timeout  (in milliseconds) used when downloading external data.                                                                                                                                                                                                                                 | 60000                                                               |
dataDirectory            | Sets the data directory to hold SQL CVEs contents. This should generally not be changed.                                                                                                                                                                                                                          | ~/.m2/repository/org/owasp/dependency-check-data/                   |
databaseDriverName       | The database driver full classname; note, only needs to be set if the driver is not JDBC4 compliant or the JAR is outside of the class path.                                                                                                                                                                      | &nbsp;                                                              |
databaseDriverPath       | The path to the database driver JAR file; only needs to be set if the driver is not in the class path.                                                                                                                                                                                                            | &nbsp;                                                              |
connectionString         | The connection string used to connect to the database.   See using a [database server](../data/database.html).                                                                                                                                                                                                    | &nbsp;                                                              |
serverId                 | The id of a server defined in the settings.xml; this can be used to encrypt the database password. See [password encryption](http://maven.apache.org/guides/mini/guide-encryption.html) for more information.                                                                                                     | &nbsp; |
databaseUser             | The username used when connecting to the database.                                                                                                                                                                                                                                                                | &nbsp;                                                              |
databasePassword         | The password used when connecting to the database.                                                                                                                                                                                                                                                                | &nbsp;                                                              |
hostedSuppressionsEnabled      | Whether the hosted suppressions file will be used.                                                                                                                                                                                                                                                                | true
hostedSuppressionsForceUpdate  | Whether the hosted suppressions file will update regardless of the `autoupdate` setting.                                                                                                                                                                                                                          | false
hostedSuppressionsUrl          | The URL to a mirrored copy of the hosted suppressions file for internet-constrained environments.                                                                                                                                                                                                                 | https://jeremylong.github.io/DependencyCheck/suppressions/publishedSuppressions.xml
hostedSuppressionsAuthHeader   | The authorization header to a mirrored copy of the hosted suppressions file for internet-constrained environments.                                                                                                                                                                                                    |
hostedSuppressionsValidForHours| Sets the number of hours to wait before checking for new updates from the NVD.                                                                                                                                                                                                                                    | 2
retireJsUrlServerId      | The id of a server defined in the settings.xml to retrieve the credentials (username and password) to connect to RetireJS instance.                                                                                                                                                                               | &nbsp;
retireJsUser             | If you don't want register user/password in settings.xml, you can specify user.                                                                                                                                                                                                                                   | &nbsp;
retireJsPassword         | If you don't want register user/password in settings.xml, you can specify user.                                                                                                                                                                                                                                   | &nbsp;

Proxy Configuration
====================
Use [Maven's settings](https://maven.apache.org/settings.html#Proxies) to configure a proxy server. Please see the
dependency-check [proxy configuration](../data/proxy.html) page for additional problem solving techniques. If multiple proxies
are configured in the Maven settings file you must tell dependency-check which proxy to use with the following property:

Property             | Description                                                                          | Default Value |
---------------------|--------------------------------------------------------------------------------------|---------------|
mavenSettingsProxyId | The id for the proxy, configured via settings.xml, that dependency-check should use. | &nbsp;        |
