About
====================
OWASP dependency-check is an open source solution to the OWASP Top 10 2021 entry:
[A06:2021 – Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/).
Dependency-check can currently be used to scan software to identify the use of 
known vulnerable components. For a full list of supported languages/technologies
please see the [File Type Analyzer](analyzers/index.html)
page). Note that some of the analyzers are experimental and may produce more false 
positive and false negative rates. To use the experimental
analyzers they must be specifically enabled via the appropriate _experimental_
configuration.

The problem with using known vulnerable components was covered in a paper by
Jeff Williams and Arshan Dabirsiaghi titled, "[The Unfortunate Reality of
Insecure Libraries](http://www1.contrastsecurity.com/the-unfortunate-reality-of-insecure-libraries?&amp;__hssc=92971330.1.1412763139545&amp;__hstc=92971330.5d71a97ce2c038f53e4109bfd029b71e.1412763139545.1412763139545.1412763139545.1&amp;hsCtaTracking=7bbb964b-eac1-454d-9d5b-cc1089659590%7C816e01cf-4d75-449a-8691-bd0c6f9946a5)"
(registration required). The gist of the paper is that we as a development
community include third party libraries in our applications that contain well
known published vulnerabilities \(such as those at the
[National Vulnerability Database](http://web.nvd.nist.gov/view/vuln/search)\).

More information about dependency-check can be found here:

* [How does dependency-check work](general/internals.html)
* [How to read the report](general/thereport.html)

**This product uses the NVD API but is not endorsed or certified by the NVD.**

OWASP dependency-check's core analysis engine can be used as:

- [Ant Task](dependency-check-ant/index.html)
- [Command Line Tool](dependency-check-cli/index.html)
- [Gradle Plugin](dependency-check-gradle/index.html)
- [Jenkins Plugin](dependency-check-jenkins/index.html)
- [Maven Plugin](dependency-check-maven/index.html) - Maven 3.6.3 or newer required

Unofficial (Not endorsed by OWASP)
- [SBT Plugin](https://github.com/nMoncho/sbt-dependency-check)

For help with dependency-check the following resource can be used:

- Open a [github issue](https://github.com/dependency-check/DependencyCheck/issues)
