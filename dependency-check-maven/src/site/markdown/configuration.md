Configuration
====================
The following properties can be set on the dependency-check-maven plugin.

Property            | Description                        | Default Value
--------------------|------------------------------------|------------------
autoUpdate          | Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to false. | true
externalReport      | When using as a Site plugin this parameter sets whether or not the external report format should be used. | false
failBuildOnCVSS     | Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is 11 which means since the CVSS scores are 0-10, by default the build will never fail.         | 11
format              | The report format to be generated (HTML, XML, VULN, ALL). This configuration option has no affect if using this within the Site plugin unless the externalReport is set to true. | HTML
logFile             | The file path to write verbose logging information. |
connectionTimeout   | The Connection Timeout.            |
proxyUrl            | The Proxy URL.                     |
proxyPort           | The Proxy Port.                    |
proxyUsername       | Defines the proxy user name.       |
proxyPassword       | Defines the proxy password.        |
whiteListedDependencies | Defines optional white-listed vulnerabilities which should be ignored. Configurable via the 'org.owasp.dependencycheck.whitelisted' (comma-separated string, eg. 'CVE-2008-6504,CVE-2006-0550') |
