Nugetconf Analyzer
==============

OWASP dependency-check includes an analyzer that will scan NuGet's packages.config files to
collect information about the component being used. The evidence collected
is used by other analyzers to determine if there are any known vulnerabilities
associated with the component.

Files Scanned: packages.config
