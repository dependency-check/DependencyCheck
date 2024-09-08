Configuration
====================
The dependency-check-update task downloads and updates the local copy of the NVD.
There are several reasons that one may want to use this task; primarily, creating
an update that will be run only once a day or once every few days (but not greater
than 7 days) and then use the `autoUpdate="false"` setting on individual
dependency-check scans. See [Internet Access Required](https://jeremylong.github.io/DependencyCheck/data/index.html)
for more information on why this task would be used.

```xml
<target name="dependency-check-update" description="Dependency-Check Update">
    <dependency-check-update />
</target>
```

Configuration: dependency-check-update Task
--------------------
The following properties can be set on the dependency-check-update task.

Property              | Description                                                                                   | Default Value
----------------------|-----------------------------------------------------------------------------------------------|------------------
proxyServer           | The Proxy Server; see the [proxy configuration](../data/proxy.html) page for more information.| &nbsp;
proxyPort             | The Proxy Port.                                                                               | &nbsp;
proxyUsername         | Defines the proxy user name.                                                                  | &nbsp;
proxyPassword         | Defines the proxy password.                                                                   | &nbsp;
nonProxyHosts         | Defines the hosts that will not be proxied.                                                   | &nbsp;
connectionTimeout     | The URL Connection Timeout (in milliseconds).                                                 | 10000
readtimeout           | The URL Read Timeout (in milliseconds).                                                       | 60000
failOnError           | Whether the build should fail if there is an error executing the update                       | true

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