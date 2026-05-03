Artifactory Analyzer
==============

The Artifactory Analyzer will check for the Maven GAV (Group/Artifact/Version) information
for artifacts in the scanned area. This is done by determining if an artifact exists
in an Artifactory installation using the SHA-1 hash of the artifact scanned. If the
artifact's hash is found in the configured Artifactory repository, its GAV is recorded as
an Identifier and the Group is collected as Vendor evidence, the Artifact is
collected as Product evidence, and the Version is collected as Version evidence.

The Artifactory Analyzer is an alternative to the [Central](./central-analyzer.html) or 
[Nexus](./nexus-analyzer.html) Analyzers and can be used to limit dependencies on 
an external resource such as Maven Central, as well 
as providing POM information for artifacts not available in Maven Central. Use by ODC
is thus similar to how users may choose to run their own Nexus instance to proxy 
artifact retrieval from Maven Central to limit internet usage and/or dependence on 
external infrastructure.

If both the Central Analyzer and Artifactory Analyzer are enabled and the Artifactory URL has not
been configured to point to an Artifactory instance the Artifactory Analyzer will
disable itself.
