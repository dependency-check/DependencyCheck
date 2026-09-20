Dependency-Check Jenkins Plugin
==============================

Dependency-Check is a utility that identifies project dependencies and checks if there are any known, publicly disclosed, vulnerabilities. This tool can be part of the solution to the OWASP Top 10 2013: A9 - Using Components with Known Vulnerabilities. This plug-in can independently execute a Dependency-Check analysis and visualize results.

[The Dependency-Check Jenkins Plugin][plugin-site]
 features the ability to perform a dependency analysis build and later view results post build. The plugin is built using [analysis-core] and features many of the same features that Jenkins static analysis plugins offer, including thresholds, charts and the ability to view vulnerability information should a dependency have one identified.

More information can be found on the [wiki], source code is available at [github].

Note, not all of the features in the HTML report produced by dependency-check, when viewed from within Jenkins, may not work correctly as [Jenkins set a restrictive CSP header](https://wiki.jenkins-ci.org/display/JENKINS/Configuring+Content+Security+Policy). This does not affect the functionality of the tool or other reporting capabilities within the Jenkins plugin. Two options to re-enable the missing features in the HTML report would be to either download the report and view it locally or modify the CSP header to allow in-line script.

Copyright & License
-------------------

Dependency-Check is Copyright (c) 2012-2026 OWASP Dependency-Check Contributors. All Rights Reserved.

Dependency-Check Jenkins Plugin is Copyright (c) 2013-2014 Steve Springett. All Rights Reserved.

Permission to modify and redistribute is granted under the terms of the Apache 2.0 license. See the [LICENSE.txt][license] file for the full license.

Dependency-Check makes use of several other open source libraries. Please see the [NOTICE.txt][notices] file for more information.


  [wiki]: https://wiki.jenkins-ci.org/display/JENKINS/OWASP+Dependency-Check+Plugin
  [analysis-core]: http://wiki.jenkins-ci.org/x/CwDgAQ
  [license]: https://github.com/jenkinsci/dependency-check-plugin/blob/master/LICENSE.txt
  [notices]: https://github.com/jenkinsci/dependency-check-plugin/blob/master/NOTICES.txt
  [plugin-site]: https://plugins.jenkins.io/dependency-check-jenkins-plugin/
  [github]: https://github.com/jenkinsci/dependency-check-plugin
