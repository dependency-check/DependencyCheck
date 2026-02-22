Central Analyzer
==============

OWASP dependency-check includes an analyzer that will check for the Maven GAV
(Group/Artifact/Version) information for artifacts in the scanned area. By
default the information comes from [Maven Central][1]. If the artifact's hash
is found in the configured Nexus repository, its GAV is recorded as an Identifier
and the Group is collected as Vendor evidence, the Artifact is collected as Product
evidence, and the Version is collected as Version evidence.

By default, this analyzer is disabled in the Maven Plugin and Gradle Task. However,
if your Gradle build relies on scanning non-Gradle artifacts or archives from other
ecosystems that contain jars, consider re-enabling the Central Analyzer using 
`analyzers.centralEnabled=true`, or use the Nexus/Artifactory analyzers as an
alternative to improve identification of JARs utilized outside the normal gradle
Java plugin.

[1]: http://search.maven.org/            "Maven Central"
