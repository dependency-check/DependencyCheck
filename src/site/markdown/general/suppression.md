Suppressing False Positives
====================
Due to [how dependency-check identifies libraries](internals.html) false positives may occur (i.e. a CPE was identified that is incorrect). Suppressing these false positives is fairly easy using the HTML report. In the report next to each CPE identified (and on CVE entries) there is a suppress button. Clicking the suppression button will create a dialogue box which you can simple hit Control-C to copy the XML that you would place into a suppression XML file. If this is the first time you are creating the suppression file you should click the "Complete XML Doc" button on the top of the dialogue box to add the necessary schema elements.

A sample suppression file would look like:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.4.xsd"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.4.xsd
                                  https://dependency-check.github.io/DependencyCheck/dependency-suppression.1.4.xsd">
   <suppress>
      <notes><![CDATA[
      file name: some.jar
      ]]></notes>
      <sha1>66734244CE86857018B023A8C56AE0635C56B6A1</sha1>
      <cpe>cpe:/a:apache:struts:2.0.0</cpe>
   </suppress>
</suppressions>
```
The above XML file will suppress the cpe:/a:apache:struts:2.0.0 from any file with the a matching SHA1 hash.

The following shows some other ways to suppress individual findings. Note the ways to select files using either
the sha1 hash or the filePath (the filePath can also be a regex). Additionally, there are several things that
can be suppressed - individual CPEs, individual CVEs, or all CVE entries below a specified CVSS score. The most common
would be suppressing CPEs based off of SHA1 hashes or filePath (regexes) - these entries can be generated using the
HTML version of the report. The other common scenario would be to ignore all CVEs below a certain CVSS threshold.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.4.xsd"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.4.xsd
                                  https://dependency-check.github.io/DependencyCheck/dependency-suppression.1.4.xsd">
    <suppress>
        <notes><![CDATA[
        This suppresses a CVE identified by OSS Index using the vulnerability name and packageUrl.
        ]]></notes>
        <packageUrl regex="true">^pkg:maven/org\.eclipse\.jetty/jetty-server@.*$</packageUrl>
        <vulnerabilityName>CVE-2017-7656</vulnerabilityName>
    </suppress>
    <suppress>
        <notes><![CDATA[
        This suppresses cpe:/a:csv:csv:1.0 for some.jar in the "c:\path\to" directory.
        ]]></notes>
        <filePath>c:\path\to\some.jar</filePath>
        <cpe>cpe:/a:csv:csv:1.0</cpe>
    </suppress>
    <suppress>
        <notes><![CDATA[
        This suppresses any jboss:jboss cpe for any test.jar in any directory.
        ]]></notes>
        <filePath regex="true">.*\btest\.jar</filePath>
        <cpe>cpe:/a:jboss:jboss</cpe>
    </suppress>
    <suppress>
        <notes><![CDATA[
        This suppresses a specific cve for any test.jar in any directory.
        ]]></notes>
        <filePath regex="true">.*\btest\.jar</filePath>
        <cve>CVE-2013-1337</cve>
    </suppress>
    <suppress>
        <notes><![CDATA[
        This suppresses a specific cve for any dependency in any directory that has the specified sha1 checksum.
        ]]></notes>
        <sha1>384FAA82E193D4E4B0546059CA09572654BC3970</sha1>
        <cve>CVE-2013-1337</cve>
    </suppress>
    <suppress>
        <notes><![CDATA[
        This suppresses all CVE entries that have a score below CVSS 7.
        ]]></notes>
        <cvssBelow>7</cvssBelow>
    </suppress>
    <suppress>
        <notes><![CDATA[
        This suppresses false positives identified on spring security.
        ]]></notes>
        <gav regex="true">org\.springframework\.security:spring.*</gav>
        <cpe>cpe:/a:vmware:springsource_spring_framework</cpe>
        <cpe>cpe:/a:springsource:spring_framework</cpe>
        <cpe>cpe:/a:mod_security:mod_security</cpe>
    </suppress>
    <suppress>
        <notes><![CDATA[
        This suppresses false positives identified on spring security.
        ]]></notes>
        <gav regex="true">org\.springframework\.security:spring.*</gav>
        <vulnerabilityName regex="true">.*</vulnerabilityName>
    </suppress>
    <suppress until="2020-01-01Z">
        <notes><![CDATA[
        This suppresses a specific cve for any dependency in any directory that has the specified sha1 checksum. If current date is not yet on or beyond 1 Jan 2020.
        ]]></notes>
        <sha1>384FAA82E193D4E4B0546059CA09572654BC3970</sha1>
        <cve>CVE-2013-1337</cve>
    </suppress>
</suppressions>
```

It is also possible to set an expiration date for a suppression rule:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.4.xsd"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.4.xsd
                                  https://dependency-check.github.io/DependencyCheck/dependency-suppression.1.4.xsd">
    <suppress until="2020-01-01Z">
        <notes><![CDATA[
        Suppresses a given CVE for a dependency with the given sha1 until the current date is 1 Jan 2020 or beyond.
        ]]></notes>
        <sha1>384FAA82E193D4E4B0546059CA09572654BC3970</sha1>
        <cve>CVE-2013-1337</cve>
    </suppress>
</suppressions>
```

Suppressions can also be configured based on CVSS scores.  The element cvssScore specifies
a score threshold.  Vulnerabilities that have any score below this threshold will be suppressed.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.4.xsd"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.4.xsd
                                  https://dependency-check.github.io/DependencyCheck/dependency-suppression.1.4.xsd">
    <suppress until="2020-01-01Z">
        <notes><![CDATA[
        Suppress any vulnerability with a score below 7
        ]]></notes>
        <cvssScore>7</cvssScore>
    </suppress>
</suppressions>
```

Suppressions can also be configured per CVSS score version.  In the example that follows a vulnerability
will be suppressed only if its CVSS v2 score is below 7, its CVSS v3 score is below 8,
and its CVSS v4 score is below 9.  If the vulnerability does not have a score for a given
version the threshold not be applied to the suppression decision.  If you specify a cvssScore 
element and cvssVnScore elements, the later will be ignored.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.4.xsd"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.4.xsd
                                  https://dependency-check.github.io/DependencyCheck/dependency-suppression.1.4.xsd">
    <suppress until="2020-01-01Z">
        <notes><![CDATA[
        Suppress any vulnerability with different threshold per CVSS version
        ]]></notes>
        <cvssV2Score>7</cvssV2Score>
        <cvssV3Score>8</cvssV3Score>
        <cvssV4Score>9</cvssV4Score>
    </suppress>
</suppressions>
```

The full schema for suppression files can be found here: [suppression.xsd](https://dependency-check.github.io/DependencyCheck/dependency-suppression.1.3.xsd "Suppression Schema")

Please see the appropriate configuration option in each interfaces configuration guide:

-  [Command Line Tool](../dependency-check-cli/arguments.html)
-  [Maven Plugin](../dependency-check-maven/configuration.html)
-  [Gradle Plugin](../dependency-check-gradle/configuration.html)
-  [Ant Task](../dependency-check-ant/configuration.html)
-  [Jenkins Plugin](../dependency-check-jenkins/index.html)
