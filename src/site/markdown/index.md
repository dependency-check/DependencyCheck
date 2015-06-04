About
====================
OWASP dependency-check is an open source solution the OWASP Top 10 2013 entry:
[A9 - Using Components with Known Vulnerabilities](https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities).
Dependency-check can currently be used to scan Java, .NET and Python
applications (and their dependent libraries) to identify known vulnerable
components.

The problem with using known vulnerable components was covered in a paper by
Jeff Williams and Arshan Dabirsiaghi titled, "[The Unfortunate Reality of
Insecure Libraries](http://www1.contrastsecurity.com/the-unfortunate-reality-of-insecure-libraries?&amp;__hssc=92971330.1.1412763139545&amp;__hstc=92971330.5d71a97ce2c038f53e4109bfd029b71e.1412763139545.1412763139545.1412763139545.1&amp;hsCtaTracking=7bbb964b-eac1-454d-9d5b-cc1089659590%7C816e01cf-4d75-449a-8691-bd0c6f9946a5)"
(registration required). The gist of the paper is that we as a development
community include third party libraries in our applications that contain well
known published vulnerabilities \(such as those at the
[National Vulnerability Database](http://web.nvd.nist.gov/view/vuln/search)\).

More information about dependency-check can be found here:

* [How does dependency-check work](./internals.html)
* [How to read the report](./thereport.html)
* [The OWASP dependency-check mailing list](./mail-lists.html)

OWASP dependency-check's core analysis engine can be used as:

- [Command Line Tool](dependency-check-cli/index.html)
- [Maven Plugin](dependency-check-maven/index.html)
- [Ant Task](dependency-check-ant/index.html)
- In a [Gradle Build](./gradle.html)
- [Jenkins Plugin](dependency-check-jenkins/index.html)
