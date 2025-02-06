# Proxy Configuration

With dependency-check 9.x the proxy configuration is unfortunately in transition
and, if required, will likely need to be **configured twice**.

## Java Properties

The go-forward proxy configuration is done using Apache HTTPClient system property proxy configuration
which can be set using an environment variable `JAVA_TOOL_OPTIONS`.
See https://hc.apache.org/httpcomponents-client-5.4.x/current/httpclient5/apidocs/org/apache/hc/client5/http/impl/classic/HttpClientBuilder.html for
more information. The recommended properties that can be configured are:

- https.proxyHost
- https.proxyPort
- https.proxyUser
- https.proxyPassword
- http.nonProxyHosts

And in case of legacy URLs that are not (yet) exposing on https:
- http.proxyHost
- http.proxyPort
- http.proxyUser
- http.proxyPassword


As example configuration would be:

```bash
export JAVA_TOOL_OPTIONS="-Dhttps.proxyHost=my-proxy.internal -Dhttps.proxyPort=8083"
```

If you have some custom internal URLs that are on plain http, but do require use of the proxy you should also add
the `http.*` properties for the proxy.

```bash
export JAVA_TOOL_OPTIONS="-Dhttps.proxyHost=my-proxy.internal -Dhttps.proxyPort=8083 -Dhttp.proxyHost=my-proxy.internal -Dhttp.proxyPort=8083"
```

## Legacy configuration

Legacy proxy configuration can be configured in any of the dependency-check integrations 
(CLI, Maven, Gradle, Ant, Jenkins). See the configuration settings for each:

* [Maven Plugin](https://dependency-check.github.io/DependencyCheck/dependency-check-maven/configuration.html)
* [Gradle Plugin](https://dependency-check.github.io/DependencyCheck/dependency-check-gradle/configuration.html)
* [Ant Task](https://dependency-check.github.io/DependencyCheck/dependency-check-ant/configuration.html)
* [Command Line](https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html)

Certificate Errors
------------------
In some cases if you setup a proxy the connection may still fail due to certificate
errors (see the log file from dependency-check). If you know which cert it's failing 
on (either your proxy or NVD/CVE) you can either add the certificate itself or the 
signing chain to your trust store. If you don't have access to modify the system 
trust store (in $JAVA_HOME/lib/security/cacerts) you can copy it elsewhere and 
import it using keytool, then specify that trust store on the command line 
(`mvn -Djavax.net.ssl.trustStore=/path/to/cacerts`) or if you need to always 
have that set, you can set the environment variable `JAVA_TOOL_OPTIONS` to have 
`-Djavax.net.ssl.trustStore=/path/to/cacerts`.

Still failing?
--------------
In some cases the proxy is configured to block `HEAD` requests. While an attempt
is made by dependency-check to identify this situation it does not appear to be
100% successful. As such, the last thing to try is to add the property 
`mvn -Ddownloader.quick.query.timestamp=false`.

If trying the above and it still fails please open a ticket in the 
[github repo](https://github.com/dependency-check/DependencyCheck/issues).