# Change Log

## [Version 12.0.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v12.0.1) (2025-01-29)

- fix: correct JSON report error (#7350)
- fix: some compatability issues in the gitlab report (#7349)
- fix: ArtifactoryAnalyzer updated to use the HTTPClient5-based Downloader and skip unusable results (#7293)
- chore: allow messages via EngineVersionCheck (#7353)
- chore: switch from javax.json to jakarta.json (#7326)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/93?closed=1).

## [Version 12.0.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v12.0.1) (2025-01-19)

- docs: Fix OSS Index Maven config documentation (#7322)
- Fix OSS Index Maven config documentation
- chore(docs): Document Gradle plugin support for failBuildOnUnusedSuppressionRule (#7307)
- chore(docs): Correct analyzers config example to use Gradle dot-syntax (#7305)
- fix: improve error message on improperly configured serverId credentials in settings.xml (#7313)
- fix: Lower Basic serverId when Bearer was expected to a warning
- fix: improve error message on improperly configured serverId credentials
- fix: Correct nonProxyHosts support when no sys properties set (#7306)
- core(docs): Group failBuildOnUnusedSuppressionRule flag next to suppression file configuration
- core(docs): Update Gradle plugin documentation for failBuildOnUnusedSuppressionRule support
- fix: Correct nonProxyHosts support when no sys properties set
- chore(docs): Correct analyzers config example to use Gradle dot-syntax

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/92?closed=1). 

## [Version 12.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v12.0.0) (2025-01-11)

- feat: report on CVSS v4 (#7204)
- feat: show from which dependency the CVE comes in failure report (#7224)
- feat: Use Maven settings decryption API for decrypting secrets from settings.xml (#7284)
- feat: Extend authentication to support Bearer token for many resources (#7277)
- feat: Add a flag to fail when one or more suppression rules are not used (#7244)
- fix: add product evidence as vendor to reduce FN (#7295)
- fix: Make the HTTP-Client use pre-emptive authentication (#7255)
- fix: Add the missing proxy credentials for suppressionFileUser/Password authentication scenario
- fix: increase max retry count (#7252)
- fix: Make the HTTP-Client use pre-emptive authentication for configured server credentials and extend HTTPClient usage to Nexus search
- fix: Tranform into UTC the last modified date from database (#7222)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/91?closed=1). 

## [Version 11.1.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v11.1.1) (2024-12-04)

- fix: re-enable issue locking (#7220)
- fix: add username/password properties to be able to authenticate for central.content.url and analyzer.central.url again (#7169)
- fix: rework replaceOrAddVulnerability (#7177)
- fix: do not log loading of JDBC driver (#7155)
- fix: expose flag to disable version check (#7147)
- fix: Gracefully handle CVEs with bad configuration nodes missing CPE match expressions (#7125)
- chore: cleanup base suppression (#7138)
- docs: update gradle configuration documentation (#7176)
- docs: update documentation for Gradle plugin (#7143)
- docs: improve false positive issue templat (#7130)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/90?closed=1). 

## [Version 11.1.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v11.1.0) (2024-10-30)

- feat: PHP Composer Analyzer now scans packages-dev by default (#7114)
  - Users can configure if packages-dev should be skipped
- fix(regression): re-add h2 database driver name (#7115) 
- fix(regression): Make the Downloader honour the proxy.nonproxyhosts ODC Setting (#7077)
- fix: do not set legacy proxy from maven or env (#7072) (#7074)
- docs: add missing documentation for the MS Build Analyzer (#7113)
- docs: Document the breaking change for Maven plugin as reporting plugin (#7079)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/89?closed=1). 

## [Version 11.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v11.0.0) (2024-10-21)

- **breaking change**: Switch from JMockit to Mockito & build target to Java 11 (#6922)
  - dependency-check now requires a minimum of Java 11.0 to run
- **breaking change**: bump com.h2database:h2 from 2.1.214 to 2.3.232 (#6132)
  - H2 databases generated with an older version of ODC will not work with ODC 11.0.0; a new H2 db must be generated
- **breaking change**: Maven plugin updated to Doxia 2.x reporting stack
  - Users of the Maven plugin that configure it as a reporting plugin will need to use maven-site-plugin 3.20.0 or later (#6959)
- feat: Replace old Downloader by an Apache HTTPClient based downloader
- feat: Use Apache HTTPClient for downloads of public resources (#6949)
- feat: Also make NodeAuditSearch usr our HTTPClient based connections
- feat: Also make OSSIndexAnalyzer use our HTTPClient based connections
- feat: Migrate CentralSearch to use Apache HTTP-client via Downloader
- feat: Extend apache HTTP-client usage to EngineVersionCheck
- feat: Remove the need to specify dbDriver for external databases using JDBCv4 ServiceLoader supporting JDBC drivers (#6938)
- fix: use latest generated suppressions (#7064)
- fix: Fixup parameter sequence for Dowloader credentials (#7033)
- fix: Fixup the missing addition of NVD API Datafeed credentials (if configured)
- fix: Fixup broken proxy authentication in first attempt; extend to include KEV downloads
- fix: store timestamps locally for local resources (#6936)
- build: Remove the animal-sniffer, propagate java version to plugin-archetype (#6950)
- build: Update Checkstyle configuration and Suppression DTD references (#6951)
- chore: Update test db schema (#7036)
- chore: remove old, unneeded database upgrade script
- docs: reformat javadoc (#7009)
- docs: Fixup javadoc warnings (#6995)
- chore: Replace use of several deprecated methods/classes by their successors (#6933)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/87?closed=1). 

## [Version 10.0.4](https://github.com/jeremylong/DependencyCheck/releases/tag/v10.0.4) (2024-09-01)

 - build(deps): exclude unused dependency (#6916)
 - fix: improve regex (#6917)
 - fix: correctly handle null values in cpeMatch (#6915)
 - fix(site): Update Fluido skin to resolve broken fork-me-on-github image (#6914)
 - fix: do not report over 100% download complete (#6899)
 - fix: Correct spelling of occurring in NvdApiDataSource.java (#6883)
 - fix: skip blank lines in requirements.txt (#6867)
 - fix: correct percentage calculation (#6868)
 - docs: remove old recommendation (#6860)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/88?closed=1). 

## [Version 10.0.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v10.0.3) (2024-07-16)

- feat: Enable configuration of a lower resultsPerPage on NVD API (#6843)
- build(deps): bump open-vulnerability-clients from 6.1.6 to 6.1.7 (#6848)
- build(deps): bump JamesIves/github-pages-deploy-action from 4.6.1 to 4.6.3 (#6814)
- build(deps): bump org.codehaus.mojo:versions-maven-plugin from 2.16.2 to 2.17.0 (#6762)
- build(deps): bump org.apache.maven.plugins:maven-checkstyle-plugin from 3.3.1 to 3.4.0 (#6815)
- build(deps): bump golang from 1.22.4-alpine to 1.22.5-alpine (#6805)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/84?closed=1). 

## [Version 10.0.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v10.0.2) (2024-07-06)

**Mandatory Upgrade** - due to older versions of dependency-check causing numerous, spurious requests that end in processing failures, this upgrade is mandatory so that the NVD can differentiate valid requests and block the old clients.

- build(deps): bump open-vulnerability-clients (#6810)
- fix(db): #6788 removing redundant db index "idxVulnerability" on "vulnerability.cve" (#6807)
- docs: Further improve formatting and docs of H2 database caching strats (#6804)
- fix: update_vulnerability in dbStatements_oracle.properties (#6803)
- fix: fix NPE  (#6778)
- fix: add hint to resolve false negative (#6802)
- chore: update configure (#6794)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/86?closed=1). 

## [Version 10.0.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v10.0.1) (2024-07-02)

- build(deps): bump open-vulnerability-client (#6772)
- fix: remove debug logging (#6770)
- fix: postgresql column count error (#6773)
- fix: mssql column name and version (#6761)
- docs: update supported versions (#6771)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/85?closed=1). 

## [Version 10.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v10.0.0) (2024-07-01)

- **breaking change**: upgrade to dotnet 8.0 (#6580)
  - Users of the AssemblyAnalyzer must upgrade/utilize dotnet 8 to analyze assemblies
- feat: fix the NVD API related errors by adding cvssV4 support (#6756)
   - **breaking changes**: anyone utilizing a centralized database will need to upgrade the schema; see changes in [PR #6756](https://github.com/jeremylong/DependencyCheck/pull/6756/files#diff-ca432c4b41d39caa84d140e06694b09c7e6394c8a2db72ba27516dc77ee3bd67)
- fix: avoid escaping unnecessary chars in HTML report suppression regexes (#6749)
- fix: #6688 Trim version number when parsin POM (#6705)
- fix: change request if lockfile is file v3 (#6690)
- fix: skip pyproject.toml unless it contains `tool.poetry` before ensuring lockfiles (#6681)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/83?closed=1). 

## [Version 9.2.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v9.2.0) (2024-05-15)

 - docs: update logo per intellj (#6660)
 - feat: Carthage analyzer (#6614)
 - fix: Ensure valid JSON output for gitlab report (#6630)
 - feat: Support Package.swift version 3 Specification (#6578)
 - chore: Update the packaged suppressions to include new hosted suppressions (#6567)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/82?closed=1). 

## [Version 9.1.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v9.1.0) (2024-03-31)

- feat: Add v2 support for maven_install.json (#6528)
- build(deps): bump open-vulnerability-client (#6554)
  - resolves update issues due to CVSS Metrics 4.0
- build(deps): bump jackson.version from 2.16.0 to 2.16.1 (#6353)
- build(deps): bump org.jsoup:jsoup from 1.16.2 to 1.17.2 (#6362)
- build(deps): bump golang from 1.21.5-alpine to 1.22.1-alpine (#6506)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/81?closed=1).

## [Version 9.0.10](https://github.com/jeremylong/DependencyCheck/releases/tag/v9.0.10) (2024-03-15)

- fix: #4321 Suppress redis server CVEs for client libraries (#4321) (#6489)
- fix: bump commons-compress from 1.25.0 to 1.26.0 to fix CVE-2024-25710 and CVE-2024-26308 (#6492)
- feat: Allow to pass NVD API key via environment variable (#6454)
- fix: issue 5452 - ConcurrentModificationException in NodePackageAnalyzer.processDependencies - adding synchronized block  (#6501)
- docs: document the default data directory (#6484)
- fix: prevent NPE in bundler audit (#6462)
- fix: #6441 Improve suppression rule to not restrict to a single version (#6442)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/80?closed=1).

## [Version 9.0.9](https://github.com/jeremylong/DependencyCheck/releases/tag/v9.0.9) (2024-01-17)

- fix: for #6374 to delete non-empty directories (#6375)
- fix: NoSuchMethodError closeQuietly(java.io.Closeable[]) (#6377)
- chore: close stream to prevent possible resource leak (#6382)
- docs: Document default for CLI --data (#6359)
- docs: document gradle build (#6371)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/79?closed=1).

## [Version 9.0.8](https://github.com/jeremylong/DependencyCheck/releases/tag/v9.0.8) (2024-01-06)

- fix: favor stability over performance (#6349)
- chore: replace commons-io with core java calls (#6343)
- fix: improve error reporting for invalid H2 database (#6339)
- fix: rework fix for closing input streams on errors correctly (#6338)
- fix: reduce chance NVD API block updates due to rate limit (#6333)
- fix: ensure open handles will not leak on errors (#6326)
- fix: improve error reporting (#6324)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/78?closed=1).

## [Version 9.0.7](https://github.com/jeremylong/DependencyCheck/releases/tag/v9.0.7) (2023-12-18)

- docs: document insecure configuration for GHSA-qqhq-8r2c-c3f5 (#6315)
- fix: improve memory usage on NVD update (#6321)
- fix: skip pyproject.toml unless it contains `tool.poetry` (#6316)
- fix: resolve build error that may cause an issue on some JDK versions (#6312)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/77?closed=1).

## [Version 9.0.6](https://github.com/jeremylong/DependencyCheck/releases/tag/v9.0.6) (2023-12-15)

- build: bump open-vulnerability-clients@5.1.1 (#6308)
- fix: mask nvd.api.key in logs; see GHSA-qqhq-8r2c-c3f5 (#6307)
- fix: update java version check (#6297)
- fix: more efficient memory usage (#6299)
- fix: stream NVD data via Jackson to reduce memory footprint (#6275)
- docs: document github action caching (#6301)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/76?closed=1).

## [Version 9.0.5](https://github.com/jeremylong/DependencyCheck/releases/tag/v9.0.5) (2023-12-13)

- fix: make NVD API endpoint configurable (#6287)
- fix: synch last modified timestamp for NVD API (#6281)
- fix: read NVD cache meta files if cache.properties does not exist (#6282)
- fix: correct property for nonProxyHosts (#6285)
- fix: reduce apache http logging (#6280)
- fix: store last modified timestamp for RetireJS and the Hosted Suppression File in db (#6271)
- build: bump golang in the docker image (#6274)
- fix: use temporary files to reduce memory usage during the NVD Update (#6270)
- fix: use BIT for Oracle DB instead of Boolean when calling prepared statements (#6264)
- fix: showing all reference tags in reports (#6259)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/75?closed=1).

## [Version 9.0.4](https://github.com/jeremylong/DependencyCheck/releases/tag/v9.0.4) (2023-12-08)

- fix: utilize maven proxy if present (#6255)
- fix: allow api key in cli to be quoted (#6253)
- fix: use correct maven plugin reporting plugin (#6244)
- fix: correct trailing comma in JSON report (#6245)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/74?closed=1).

## [Version 9.0.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v9.0.3) (2023-12-06)

- fix: use Java properties for proxy configuration (#6238)
- docs: update proxy configuration documentation (#6237)
- docs: add documentation on caching (#6204)
- docs: Clarify H2 database caching strategy (#6220)
- docs: Update list of supported report formats (#6224)
- docs: example 5 with new nvdDatafeedUrl parameter (#6215)
- fix: prevent NPEs (#6232 and #6206)
- fix: check valid for hours for NVD API (#6225)
- fix: correct NVD cache last checked logic (#6218)
- fix: nvd datafeed should process current year (#6213)
- fix: correct references to cvssv2 and cvssv3 fields in json and xml reports (#6212)
- fix: correct name on reference links in report (#6205)
- fix: flaws int the gitlab report (#6193)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/73?closed=1).

## [Version 9.0.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v9.0.2) (2023-12-01)

- fix: remove virtual match string on NVD API Request (#6177)
- fix: correct meta data in report after switching the NVD API (#6154)
- fix: retry HTTP connections to NVD on 502 and 504 errors (#6151)
- fix: Gitlab report format needs severity capitalized (#6182)
- fix: improve JDK update version parsing (#6163)
- fix: mute JCS logging (again) (#6153)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/72?closed=1).

## [Version 9.0.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v9.0.1) (2023-11-26)

**breaking changes**: See the [upgrade notice](https://github.com/jeremylong/DependencyCheck#900-upgrade-notice)

- fix: check java 8 update version; minimum JRE is 8 update 251 (#6118)
- fix: add retry for failed NVD API requests (#6136)
- docs: add default values to documentation for the NVD API Delay (#6135)
- chore: Revert "build(deps): bump com.h2database:h2 from 2.1.214 to 2.2.224" (#6131)
  - this is a **breaking change** for anyone that successfully created the H2 database with 9.0.0.
- fix: mute jcs logging (#6130)
- docs: update NVD notice (#6110)
- fix: Use the correct key for NVD API-Key from Maven Settings serverId (#6109)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/71?closed=1).

## [Version 9.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v9.0.0) (2023-11-22)

**breaking changes**: See the [upgrade notice](https://github.com/jeremylong/DependencyCheck#900-upgrade-notice)

- feat: Utilize NVD API (#5978)
- feat: gitlab dependency scanner report format #5919 (#5920)
- fix: Use ASCII apostrophe for console message (#6076)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/68?closed=1).

## [Version 8.4.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.4.3) (2023-11-15)

- fix: bump jcs3 (#6047)
- docs: Corrected docs on hostedSuppressions (#6035)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/70?closed=1).

## [Version 8.4.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.4.2) (2023-10-22)

- fix: correct log configuration in cli (#6002)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/69?closed=1).

## [Version 8.4.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.4.1) (2023-10-21)

### Fixed

- fix: upgrade to JCS3 (#5114)
- fix: Support ~= version specifier in requirements.txt and pipfile (#5902)
- fix: Version of dependency no longer ignored when CPE product has a 'java' suffix in a product name (#5901)
- fix: Do not filter out evidences added by hints (#5900)
- fix: fixes FP #5925 (#5927)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/67?closed=1).

## [Version 8.4.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.4.0) (2023-08-19)

### Added

- feat: Add support for Nexus v3 to NexusAnalyzer (#5849)

### Fixed

- fix: Hint Analyzer should run before VersionFilter Analyzer (#5818)
- chore: switch to sha1-pinning as suggested by Semgrep
- fix: OSS Index Analyzer SocketTimeoutException exception handling based on warn only parameter (#5845)
- fix: use curl with -L to follow github redirect (#5808)
- fix: use curl with -L to follow github redirect
- fix: #5671 out of memory error (#5789)
- fix: #5671 Exit method as soon as we detect a loop to prevent an infinite loop leading to an OutOfMemoryError

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/66?closed=1).

## [Version 8.3.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.3.1) (2023-06-12)

Re-release of 8.3.0 as 8.3.1.

## [Version 8.3.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.3.0) (2023-06-12)

### Added

 - Add LibmanAnalyzer (#5652)
 - Update HTML report Dependencies header based on display settings (#5619)
 - Add link to suppressed vulnerabilities header in HTML report (#5620)
 - Enable local proxy configuration in maven plugin configuration (#5696)

### Fixed

 - Fix npm alias present in requires of dependencies (#5703)
 - Make Central URL configurable via CLI (#5667)
 - Ensure support of CVSSv3.1 (#5602)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/65?closed=1).

## [Version 8.2.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.2.1) (2023-03-23)

### Fixed

 - NullPointerException in MSBuildAnalyzer (#5589)
 - SQL Syntax for Oracle (#5590)
 - Use `https://` URLs in report templates (#5582)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/64?closed=1).

## [Version 8.2.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.2.0) (2023-03-22)

### Added

 - Support msbuild Directory.build.props (#5475)
 - better display of NPM audit references
 - Add CVSS V3 results from NPM Audit results

### Fixed

 - Fix several issues on NPM Audit reporting (#5546)
 - Case issue in SQL (#5557)
 - Fix CWE(s) extraction for NPM Audit advisories
 - Use the stable github_advisory_id instead of the now unstable id in NPM audit results

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/63?closed=1).

## [Version 8.1.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.1.2) (2023-02-28)

### Fixed

 - Fix `NullPointerException` in the Jar Analyzer introduced in 8.1.1 (#5512)
 
See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/62?closed=1).

## [Version 8.1.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.1.1) (2023-02-27)

### Fixed

 - allow hosted suppressions file to be disabled (#5509)
 - Several FPs not suitable for our automation (#5504)
 - Fix incorrect defaults for nexus and central-analyzer in gradle plugin documentation (#5503)
 - Erroneous error-log for deprecated CLI flag usage when using properyfile based disablement of Node Audit Analyzer (#5487)
 - Prefer pom.properties G/A/V over pom.xml G/A/V to resolve GAV interpolation issues (#5473)
 - Node package dependencies ending up as related dependency of the wrong version of the package (#5479)
 - do not throw error if pyproject.toml is in node_modules (#5470)
 
See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/61?closed=1).

## [Version 8.1.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.1.0) (2023-01-26)

### Added

- `Pipefile.lock` files are now supported ([#5404](https://github.com/jeremylong/DependencyCheck/pull/5404)).
- Python projects with only a `pyproject.toml` but no lock file or requirements will report an error as ODC is unable to analyze the project ([#5409](https://github.com/jeremylong/DependencyCheck/pull/5409)).

### Fixed

- Some maven projects caused false positives due to bad string interpolation ([#5421](https://github.com/jeremylong/DependencyCheck/pull/5421)).
- Error message from Assembly Analyzer has been updated to emphasize dotnet 6 is required for analysis ([#5408](https://github.com/jeremylong/DependencyCheck/pull/5408)).
- Correct issue where database defrag occurs even when no updates were performed ([#5441](https://github.com/jeremylong/DependencyCheck/pull/5441)).
- Fixed several False Positives and one False Negative.
- Fixed the `format` configuration more flexible in the gradle plugin ([dependency-check-gradle/#324](https://github.com/dependency-check/dependency-check-gradle/pull/324)).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/60?closed=1).

## [Version 8.0.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.0.2) (2023-01-26)

### Fixed

- Resolved bug causing an issue with some Maven Extensions ([#5366](https://github.com/jeremylong/DependencyCheck/pull/5366)).
- ArchiveAnalyzer will now correctly throw an exception if it cannot open an Archive ([#5371](https://github.com/jeremylong/DependencyCheck/pull/5371)).
- Updated CSV report so that it no longer has a duplicate `description` column ([#5364](https://github.com/jeremylong/DependencyCheck/pull/5364)).
- Moved several logging statements to trace which should drastically reduce the log size ([#5350](https://github.com/jeremylong/DependencyCheck/pull/5350)).
- Fixed bug with RetireJS' `--retirejsFilterNonVulnerable` and `--retirejsFilter` when used with the CLI ([#5351](https://github.com/jeremylong/DependencyCheck/pull/5351)).
- Fixed the `sarif` report format and added validation ([#5345](https://github.com/jeremylong/DependencyCheck/pull/5345) and ([#5363](https://github.com/jeremylong/DependencyCheck/pull/5363))
- Fixed `MalformedPackageException` in the gradle plugin ([dependency-check-gradle/#320](https://github.com/dependency-check/dependency-check-gradle/pull/320)).
- Fixed `MissingMethodException` in the gradle plugin ([dependency-check-gradle/#316](https://github.com/dependency-check/dependency-check-gradle/pull/316)).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/59?closed=1).

## [Version 8.0.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.0.1) (2023-01-18)

### Fixed

- Fixed Stack Overflow Exception in the gradle plugin ([dependency-check-gradle/#308](https://github.com/dependency-check/dependency-check-gradle/pull/308)).
- Fixed No Signature of Method Exception in the gradle plugin ([dependency-check-gradle/#305](https://github.com/dependency-check/dependency-check-gradle/pull/305)).
- Updated DB initialization scripts for externally hosted DBs ([#5314](https://github.com/jeremylong/DependencyCheck/pull/5314) and [#5317](https://github.com/jeremylong/DependencyCheck/pull/5317)).
  - Postgres users will need to use the updated init script and 8.0.1.
- Resolved NPE in the NodePackageAnalyzer ([#5339](https://github.com/jeremylong/DependencyCheck/pull/5339)).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/58?closed=1).

## [Version 8.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v8.0.0) (2023-01-15)

### Added

- Utilize the hosted suppression file to allow for faster remediation of reported False Positives ([#4723](https://github.com/jeremylong/DependencyCheck/issues/4723)).
- Include the [CISA Known Exploited Vulnerability Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) ([#4878](https://github.com/jeremylong/DependencyCheck/issues/4878)).
- The `gradle` and `maven` plugins now have the capability to scan the build plugins ([#4035](https://github.com/jeremylong/DependencyCheck/issues/4035)).
- The `gradle` and `maven` plugins, for transitive dependencies, will report the root dependency in the project that included the transitive dependency ([#5001](https://github.com/jeremylong/DependencyCheck/pull/5001)).
- Added `properties.security-severity` to SARIF report for better integration with GitHub Security Code scanning ([#5277](https://github.com/jeremylong/DependencyCheck/pull/5227)).
- Allow for HTTP auth settings for Retire JS repository ([#5209](https://github.com/jeremylong/DependencyCheck/pull/5209)).
- New schema for the XML report was added to support some of the above additions ([#5296](https://github.com/jeremylong/DependencyCheck/pull/5296)).
- Added missing gradle option to only warn on remote errors from the OSS Index Analyzer ([gradle #303](https://github.com/dependency-check/dependency-check-gradle/pull/303)).

### Changed

- **Breaking:** the database schema updated - if using an external database the update scripts must be run!
- The [exit codes](https://tldp.org/LDP/abs/html/exit-status.html) from the CLI have been changed to be in the range from 0-255 ([#4511](https://github.com/jeremylong/DependencyCheck/pull/4511).
- The OSS Index Analyzer will automatically disable itself if a transport error occurs - preventing copious errors from being reported ([#5300](https://github.com/jeremylong/DependencyCheck/pull/5300])).


### Fixed

- Added an additional check for rejected CVEs to reduce FP ([#5268](https://github.com/jeremylong/DependencyCheck/pull/5268).
- Corrected the analysis of `node_modules` to prevent NPEs ([#5266](https://github.com/jeremylong/DependencyCheck/pull/5266)).
- Fixed error when scanning node packages with local dependencies ([#5235](https://github.com/jeremylong/DependencyCheck/pull/5235)).
- Fixed NPE in the MSBuild Analyzer ([#5293](https://github.com/jeremylong/DependencyCheck/pull/5293)).
- Several False Positives have been resolved.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/46?closed=1).

## [Version 7.4.4](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.4.4) (2023-01-06)

### Fixed

- Resolved issue processing NVD CVE data due to column width (#5229)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/56?closed=1).

## [Version 7.4.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.4.3) (2022-12-29)

### Fixed

- Fixed NPE when analyzing version ranges in NPM (#5158 & #5190)
- Resolved several FP (#5191)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/55?closed=1).

## [Version 7.4.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.4.2) (2022-12-28)

### Fixed

- Fixes maven 3.1 compatibility issue (#5152)
- Fixed issue with invalid `node_module` paths in some scans (#5135)
- Fixed missing option to disable the Poetry Analyzer in the CLI (#5160)
- Fixed missing option to configure the OSS Index URL in the CLI (#5180)
- Fixed NPE when analyzing version ranges in NPM (#5158)
- Fixed issue with non-proxy host in the gradle plugin (https://github.com/dependency-check/dependency-check-gradle/pull/298)
- Resolved several FP

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/54?closed=1).

## [Version 7.4.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.4.1) (2022-12-09)

### Fixed

- Fixed bug when setting the proxy port in gradle (#5123)
- Fixed issue with invalid `node_module` paths in some scans (#5127)
- Resolved several FP

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/53?closed=1).

## [Version 7.4.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.4.0) (2022-12-04)

### Added

- Add support for npm package lock v2 and v3 (#5078)
- Added experimental support for Python Poetry (#5025)
- Added a vanilla HTML report for use in Jenkins (#5053)

### Changed

- Renamed `RELEASE_NOTES.md` to `CHANGELOG.md` to be more conventional
- Optimized checksum calculation to improve performance (#5112)
- Added support for scanning .NET assemblies when only the dotnet runtime is installed (#5087)
- Bumped several dependencies

### Fixed

- Fixed bug when setting the proxy port (#5076)
- Resolved several FP and FN

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/52?closed=1).

## [Version 7.3.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.3.2) (2022-11-18)

### Changed

- Automated release of 7.3.1 failed and only published to Central; 7.3.2 is a re-release of 7.3.1.
- Resolved several false positives and false negatives.
- Use Jackson Afterburner if still on Java 8 (#4966).
- Exclude `node_modules` from the Maven plugin's scan path (#4974).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/51?closed=1).

## [Version 7.3.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.3.1) (2022-11-16)

### Changed

- Resolved several false positives and false negatives.
- Use Jackson Afterburner if still on Java 8 (#4966).
- Exclude `node_modules` from the Maven plugin's scan path (#4974).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/51?closed=1).

## [Version 7.3.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.3.0) (2022-10-19)

### Added

- Added an experimental Dart analyzer (#4869).

### Changed

- Migrated from Jackson Afterburner to Blackbird (#4905).

### Fixed

- Fixed issue with the Maven plugin that caused concurrent modification exceptions (#4935).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/50?closed=1).

## [Version 7.2.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.2.1) (2022-09-20)

### Fixed

- Fixed logging issue (#4846).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/49?closed=1).

## [Version 7.2.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.2.0) (2022-09-14)

### Changed

- Add support for Bazel's pinned `maven_install.json` (#4772).
- Fixed bug preventing the use of custom report templates (#4800).
- Updated several dependencies including upgrades for dependencies with CVEs.
- Several bug fixes made and suppression rules were added.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/48?closed=1).

## [Version 7.1.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.1.2) (2022-08-20)

### Changed

- The maven plugin now includes pnpm and yarn lock files in the scan by default (#4753).
- If a suppression rule is no longer used a log entry will be written (#4685).
- Several bug fixes made and suppression rules added.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/47?closed=1).

## [Version 7.1.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.1.1) (2022-06-12)

### Fixed

- Minor bug fixes.
- Resolved several false positives.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/45?closed=1).

## [Version 7.1.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.1.0) (2022-04-23)

### Changed

- Improved sorting in the HTML report ([see #4112](https://github.com/jeremylong/DependencyCheck/issues/4112)).
- Improved support for Swift ([see #4265](https://github.com/jeremylong/DependencyCheck/pull/4265)).
- Resolved several false positives.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/45?closed=1).

## [Version 7.0.4](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.0.4) (2022-03-30)

### Changed

- Update to `jackson-databind` (see #4285).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/43?closed=1).

## [Version 7.0.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.0.3) (2022-03-29)

### Changed

- Update to `jackson-databind` (see #4285).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/42?closed=1).

## [Version 7.0.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.0.2) (2022-03-28)

### Changed

- General project maintenance, bug fixes, and false positive and false negative reductions.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/41?closed=1).

## [Version 7.0.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.0.1) (2022-03-23)

### Changed

- General project maintenance, bug fixes, and false positive reductions.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/40?closed=1).

## [Version 7.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v7.0.0) (2022-02-28)

### Changed

- **Breaking:** The H2 database version has been upgraded.
  - if you use the `dataDirectory` option you will need to run a purge after upgrading.
- **Breaking:** Upgraded to dotnet core 6.0. If analyzing dotnet assemblies the system will need to have the dotnet core 6.0.x runtime available.
- The Sarif report format has been fixed and can now be imported into GitHub if desired (See #3993).
- Introduced IssueOps for False Positive reports to assist the team in evaluating FP reports.
  - [Create New FP Report Issue](https://github.com/jeremylong/DependencyCheck/issues/new?assignees=&labels=FP+Report&template=false-positive-report.yml&title=%5BFP%5D%3A+).
- When analyzing Java projects ODC now includes data from the developers section. 
  - This will likely cause false positives on things like Apache James, please report the FP and we will fix these quickly.
- General project maintenance, bug fixes, and false positive reductions.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/28?closed=1).

## [Version 6.5.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.5.3) (2022-01-12)

### Changed

- Performance improvements for some Maven projects (see #3923 and #3931).
- Fixed bug in npm version handling introduced in 6.5.2 (see #3956).
- Improved the node package analyzer to correctly report the origin of a dependency (see #3970).
- General code maintenance and false positive reductions.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/39?closed=1).

## [Version 6.5.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.5.2) (2022-01-03)

### Changed

- Fixed false positives around log4j-api and Log4j-web (#3910 & #3937).
- Bug fix when processing NPM lock files (#3893).
- Added missing `pnpm` argmument to the CLI (#3916).
- General code maintenance and false positive reductions.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/38?closed=1).

## [Version 6.5.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.5.1) (2021-12-17)

### Changed

- Updated the dependency-check-maven plugin to correctly support SNAPSHOT version when a classifier is specified (#3787).
- Improved the analysis of Swift package manager (package.resolved - see #3813).
- General code maintenance and false positive reductions.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/37?closed=1).

## [Version 6.5.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.5.0) (2021-11-08)

### Changed

- Updated build configuration to create [reproducible builds](https://reproducible-builds.org/).
- Updated automated release process to work with branch protection.
- Resolved several false positives in the Java ecosystem.
- Enabled the Swift Resolved analyzer per #3735
- Improved iOS support per #3168 and #3765
- Added the a new pnpm Analyzer
- Fixed issue with some npm and yarn analysis failing due to large audit output

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/36?closed=1).

## [Version 6.4.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.4.1) (2021-10-11)

### Added

- Added download attempts with increasing wait time for `CVE meta` files from the NVD to prevent rate limiting issues (see [#3725](https://github.com/jeremylong/DependencyCheck/pull/3725)).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/35?closed=1).

## [Version 6.4.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.4.0) (2021-10-11)

### Changed

- Increased timeout between downloads from the NVD to prevent rate limiting issues (see [#3722](https://github.com/jeremylong/DependencyCheck/pull/3722)).
  - `cveStartYear` is now configurable and can be set to any year from 2002 to present.
  - `cveWaitTime` is a new configuration option to define how many milliseconds to wait between NVD downloads; default is 4000 ms (see [#3690](https://github.com/jeremylong/DependencyCheck/pull/3690)).
  - The NVD CVE data files are now being cached for up to 4 hours in case a download fails, re-running ODC will use the cached version.
- Fixed NPE in the ODC maven plugin (see [#3702](https://github.com/jeremylong/DependencyCheck/pull/3702).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/34?closed=1).

## [Version 6.3.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.3.2) (2021-09-29)

### Changed

- Reduced chance of rate limiting when download files from NVD (see [#2670](https://github.com/jeremylong/DependencyCheck/pull/3670)).
- Fixed bug causing some transitive dependencies being skipped in the odc-maven-plugin (see [#3627](https://github.com/jeremylong/DependencyCheck/pull/3627)).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/33?closed=1).

## [Version 6.3.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.3.1) (2021-09-01)

### Fixed

- Fixed [ConcurrentModificationException](https://github.com/jeremylong/DependencyCheck/issues/3618)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/32?closed=1).

## [Version 6.3.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.3.0) (2021-08-31)

### Changed

- Many updates were made to improve performance on large scans, reduce false positives, and other bug fixes.
- Increased the width of four columns in the database; if you use a an external database you should also update the width (see [upgrade_5.1.sql](https://github.com/jeremylong/DependencyCheck/blob/main/core/src/main/resources/data/upgrade_5.1.sql)).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/31?closed=1).

## [Version 6.2.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.2.2) (2021-06-10)

### Fixed

- Resolved issue with database connections introduced in 6.2.0 (see https://github.com/jeremylong/DependencyCheck/issues/3432).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/30?closed=1).

## [Version 6.2.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.2.1) (2021-06-08)

### Fixed

- Resolved issue with database connections introduced in 6.2.0 (see https://github.com/jeremylong/DependencyCheck/issues/3416).

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/29?closed=1).

## [Version 6.2.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.2.0) (2021-05-29)

### Changed

- Added an experimental Perl CPAN analyzer [#3378](https://github.com/jeremylong/DependencyCheck/pull/3378)
  - Note that the full DSL of the CPAN is not yet supported so any required dependency is analyzed (i.e. there is no way to exclude development requirements)
- Improved database performance [#3206](https://github.com/jeremylong/DependencyCheck/pull/3206)
- The archive analyzer now extracts files from RPM archives [#3226](https://github.com/jeremylong/DependencyCheck/pull/3226)
- Ensure ordered output in reports [#3243](https://github.com/jeremylong/DependencyCheck/pull/3343)
- Several minor bug fixes and updates to reduce false positives

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/27?closed=1).

## [Version 6.1.6](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.6) (2021-04-29)

### Fixed

- Resolved issue with Sarif report (#3243)
- Resolved issue with Ruby Bundle Audit (#3256)
- Several minor bug fixes and updates to reduce false positives

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/26?closed=1).

## [Version 6.1.5](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.5) (2021-03-31)

### Fixed

- Fixed a second NPE introduced in 6.1.3 (see #3246)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/25?closed=1).

## [Version 6.1.4](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.4) (2021-03-30)

### Changed

- Fixed an NPE introduced in 6.1.3 (see #3212)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/24?closed=1).

## [Version 6.1.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.3) (2021-03-22)

### Changed

- Modified the new CPE matching strategy to be more performant (#3207)
- Upgraded a vulnerable dependency (velocity-engine-core/CVE-2020-13936) (#3205)

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/23?closed=1).

## [Version 6.1.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.2) (2021-03-08)

### Changed

- Fixed a bug in the Sarif report generation.
- Fixed a bug with the Ant task not being able to read the dependency-check properties file in 6.1.1.
- Added a new CPE matching strategy to reduce false negatives.
- CLI and Ant task will no longer be published to bintray.
- Several minor bug fixes.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/22?closed=1).

## [Version 6.1.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.1) (2021-02-13)

### Changed

- Added missing configuration options for yarn and msbuild.
- Several bug fixes.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/21?closed=1).

## [Version 6.1.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.1.0) (2021-01-27)

### Changed

- Added SARIF file format per [#3081](https://github.com/jeremylong/DependencyCheck/issues/3081).
- Added support for Yarn per [#3063](https://github.com/jeremylong/DependencyCheck/pull/3063).
- False positive reduction and minor bug fixes.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/20?closed=1).

## [Version 6.0.5](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.0.5) (2021-01-07)

### Changed

- Added missing command line arguments per #3028 and #3035.
- False positive reduction and minor bug fixes.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/19?closed=1).

## [Version 6.0.4](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.0.4) (2020-12-31)

### Changed

- Minor bug fixes and reduction of false positives.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/18?closed=1).

## [Version 6.0.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.0.3) (2020-11-03)

### Changed

- Added a bash command completion script (see #2916); to add completion to your shell
  `completion-for-dependency-check.sh` can be found in the bin directory of the CLI:

   ```bash
   $ source completion-for-dependency-check.sh
   ```

- An experimental PIP File Analyzer was added (see #2877).
- Analysis of Node JS produced several false positives (see #2796); the analysis has
  been updated to reduce the number of false positives.
  - If analyzing Node JS projects it is highly recommended to disable the Node JS Analyzer
    and solely rely on the Node Audit Analyzer. There are plans to rework Node JS analysis
    in a future release.
- Support for external Oracle databases has been add for the 6.x releases (see #2899)
- Resolved several reported false positives.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/17?closed=1).

## [Version 6.0.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.0.2) (2020-09-27)

### Changed

- The project is migrating from hosting the release archives on Bintray and moving them to Github under the assets for each [release](https://github.com/jeremylong/DependencyCheck/releases)
  - **Please update any automation you have to point to the new location.**
- Npm Audit Analyzer now correctly skips dev dependencies (`--nodeAuditSkipDevDependencies`); see #2482.
- GoLang Analyzer now scans transitive dependencies; see #2680.
- Several bug fixes found in 6.0.1.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/16?closed=1).

## [Version 6.0.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.0.1) (2020-09-13)

### Changed

- Improved error messages when upgrading from 5.x to 6.x; due to breaking database changes if the old
  database schema is detected an error message is produced indicating that the old database should be purged.
- Fixed the database path for the Ant and Gradle plugins.
- Added locking around the RetireJS updates to resolve read/write conflicts in CI environments.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/15?closed=1).

## [Version 6.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v6.0.0) (2020-09-07)

### Changed

- Updated database schema; this is a *breaking change* and anyone using an external database or those whom
  specify the data directory will need recreate the database (including users of the docker image). The schema
  changes were made to:
  - Improve the CVSS data, when available, per #2547
  - Improve the way that ecosystems are determined
  - Improve the update performance of external databases
- Users with an **external Oracle** database will not be able to upgrade as https://github.com/jeremylong/DependencyCheck/issues/2755
  has not been resolved - as such, version 6.0.0 does not support Oracle.
- Users mirroring the NVD - ODC 6.0.0 requires the use of the version 1.1 data feeds
  - please ensure you are using 1.1 not the 1.0 data feed.
  
See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/14?closed=1).

## [Version 5.3.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.3.2) (2020-03-26)

### Changed

- Several bug fixes
- Full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/13?closed=1).

## [Version 5.3.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.3.1) (2020-03-10)

### Changed

- Added an experimental PE Analyzer that reads the PE headers of DLL and EXE files; see [#2448](https://github.com/jeremylong/DependencyCheck/pull/2448) and [#2446](https://github.com/jeremylong/DependencyCheck/pull/2446).
- Lots of bug fixes and updates to false positives and false negatives
  - You may see a large one time performance hit when updating the database after updating to 5.3.1

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/12?closed=1).

## [Version 5.3.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.3.0) (2020-01-15)

### Changed

- Updated the JSON report to include a new field for unscored vulnerabilities (see #2392).
- Updated the XML report to include a new attribute to flag unscored vulnerabilities (see #2392)
  - see https://github.com/jeremylong/DependencyCheck/blob/main/core/src/main/resources/schema/dependency-check.2.3.xsd
- Added an experimental analyzer that will lookup Node libraries in the NVD data feeds (see #1249)
  - `NpmCPEAnalyzer`, experimental analyzers must be enabled, controlled via property `analyzer.npm.cpe.enabled` which will be exposed as a configuration option in the next release.

See the full listing of [changes](https://github.com/jeremylong/DependencyCheck/milestone/11?closed=1).

## [Version 5.2.4](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.2.4) (2019-11-12)

### Changed

- Reverted a in 5.2.3 that caused the dependency-check.sh script to fail on some systems (including the docker image).
- Fixed issue with pretty printing the XML report.

See the full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue++is%3Aclosed+milestone%3A5.2.4).

## [Version 5.2.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.2.3) (2019-11-11)

### Changed

- Updated to use the NVD JSON 1.1 schema (see [#2273](https://github.com/jeremylong/DependencyCheck/issues/2273)).
  - This update is 100% backward compatible with the 1.0 schema if you are mirroring the 1.0 JSON files.
- Added `nonProxyHosts` to the CLI and gradle plugin.
- False positive corrections.
- General code cleanup/bug fix.

See the full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue++is%3Aclosed+milestone%3A5.2.3) and [pull requests](https://github.com/jeremylong/DependencyCheck/pulls?utf8=%E2%9C%93&q=is%3Apr+milestone%3A5.2.3+is%3Aclosed+).

## [Version 5.2.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.2.2) (2019-09-22)

### Changed

- False positive corrections
- General code cleanup/bug fix

See the full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue++is%3Aclosed+milestone%3A5.2.2).

## [Version 5.2.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.2.1) (2019-08-04)

### Changed

- Updated docker container to include additional database drivers and reduce overall image size
- Performance improvements when using some external databases
- False positive corrections
- General code cleanup/bug fix

See the full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue++is%3Aclosed+milestone%3A5.2.1).

## [Version 5.2.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.2.0) (2019-07-21)

### Changed

- Resolved formatting issues within the CSV report
- False positive corrections
- Renamed three properties within the `dependencycheck.properties`; there is no impact unless you are using a properties file in your build to control the CLI.
- Added support for rbenv for Bundle Audit Analysis (see https://github.com/jeremylong/DependencyCheck/issues/2060).

See the full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue++is%3Aclosed+milestone%3A5.2.0).

## [Version 5.1.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.1.1) (2019-07-15)

### Changed

- False positive corrections
- General code cleanup

See the full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?q=is%3Aissue+milestone%3A5.1.1+is%3Aclosed).

## [Version 5.1.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.1.0) (2019-06-28)

### Changed

- Added two experimental analyzers to support Golang.
- Updated the suppression schema to support suppressing OSS Index, RetireJS, NSP vulnerabilities, etc.
  - The HTML report now uses the 1.3 suppression schema by default to generate suppression rules.
  - See the updated examples on https://jeremylong.github.io/DependencyCheck/general/suppression.html.
- Added optional configuration to add credentials to the OSS Index analysis.
- Resolved issues when Oracle or MySQL were used as a centralized database in 5.0.0.

See the full listing of [resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aopen+milestone%3A5.1.0) and [pull requests](https://github.com/jeremylong/DependencyCheck/pulls?utf8=%E2%9C%93&q=is%3Apr+milestone%3A5.1.0).

## [Version 5.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.0.0) (2019-06-09)

### Changed

- Add caching of OSS-Index, Central Analyzer, and Node Audit analysis results.
- General bug fixes identified in the previous milestone releases; see [5.0.0 resolved issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aopen+milestone%3A5.0.0+) and [pull requests](https://github.com/jeremylong/DependencyCheck/pulls?utf8=%E2%9C%93&q=is%3Apr+milestone%3A5.0.0).

## [Version 5.0.0-M3](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.0.0-M3) (2019-05-06)

### Changed

- **Breaking:** OWASP dependency-check now uses the [NVD Meta files](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED) in addition to the `*.json.gz` files. If you have a local mirror of the NVD you must now mirror the meta data files. The [nist-data-mirror](https://github.com/stevespringett/nist-data-mirror) has been updated to include these files.

### Changed

- Several bug fixes and minor enhancements have been made; see the related [issues](https://github.com/jeremylong/DependencyCheck/issues?utf8=%E2%9C%93&q=+milestone%3A5.0.0-M3+) and [pull requests](https://github.com/jeremylong/DependencyCheck/pulls?utf8=%E2%9C%93&q=+milestone%3A5.0.0-M3+).
- Multiple report formats can be specified; if you wanted just two of the reports you no longer need to use ALL.
- A new JUNIT formatted report has been added; this provides a different way to integrate with Jenkins builds; the following example creates a JUNIT report with failures for any CVE with a CVSS score greater than or equal to 7.0 the Jenkins pipeline script shows how to publish the report:

  **`pom.xml`**

  ```xml
  <plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>5.0.0-M3</version>
    <configuration>
      <formats>
          <format>HTML</format>
          <format>JUNIT</format>
      </formats>
      <junitFailOnCVSS>7.0</junitFailOnCVSS>
    </configuration>
    <executions>
      <execution>
        <goals>
          <goal>verify</goal>
        </goals>
      </execution>
    </executions>
  </plugin>
  ```

  **`Jenkinsfile`**

  ```groovy
  stage ('Build') {
    steps {
      sh 'mvn verify'
    }
    post {
      success {
        junit 'target/dependency-check-junit.xml'
      }
    }
  }
  ```

## [Version 5.0.0-M2](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.0.0-M2) (2019-03-11)

### Changed

- **Breaking:** [dotnet core](https://dotnet.microsoft.com/download/dotnet-core/2.2) must be installed to analyze .NET assemblies.
- **Breaking:** The retire.js analyzer is no longer considered experimental and is enabled by default.

## [Version 5.0.0-M1](https://github.com/jeremylong/DependencyCheck/releases/tag/v5.0.0-M1) (2019-02-17)

### Changed

- **Breaking:** All previously deprecated arguments to the plugins and CLI have been removed.
- **Breaking:** The NVD CVE data import now uses the JSON data feeds instead of the XML data feeds.
  - The parameter names have changed if you are mirroring the data feeds locally.
- **Breaking:** For developers using the core engine the identifiers have been drastically changed;
  ODC now uses [Package URL](https://github.com/package-url/packageurl-java) for software
  identifiers and CPE objects from [CPE-Parser](https://github.com/stevespringett/CPE-Parser)
  for vulnerable library identifiers.
- All of the report formats have been updated to include the additional data from the NVD CVE JSON data feeds.
- Major re-working of the dependency to CPE matching algorithm.
- Introduced ecosystem filtering - this is an internal process that tries to ensure vulnerabilities
  from one technology stack do not appear on a dependency built using a completely different stack (e.g.
  NodeJS vulnerabilities should not show up on a .NET DLL).

## [Version 4.0.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v4.0.2) (2019-01-01)

### Added

- Added the ability for the dependency-check-maven plugin to scan the `dependencyManagement` section
  of the `pom.xml`. Note that in the default configuration the dependency management section is skipped.
  To enable this feature set `<skipDependencyManagement>false</skipDependencyManagement>`.
- If using a local Nexus server (v2 or v3 pro) it is now possible to provide authentication credentials.
  - Previous versions only worked with anonymous/unauthenticated access.
  - See [issue #977](https://github.com/jeremylong/DependencyCheck/issues/977)

### Fixed

- Updated fix for transitive dependencies with known vulnerabilities (guava and commons-collections)
  so that the upgrade occurs correctly in other integrations that utilize core; see
  [issue #1562](https://github.com/jeremylong/DependencyCheck/issues/1561#issuecomment-450112110).
- Resolved several false positives

## [Version 4.0.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v4.0.1) (2018-12-17)

### Fixed

- Fixed issue with false positives due to Lucene upgrade. See [#1531](https://github.com/jeremylong/DependencyCheck/issues/1580).
- Resolved several false positives.
- Resolved typo in documentation.

## [Version 4.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v4.0.0) (2018-11-21)

### Changed

- OWASP dependency-check no longer supports running in JRE/JDK 7; JRE/JDK 8 or higher is required run dependency-check. See [#1531](https://github.com/jeremylong/DependencyCheck/issues/1531).

### Fixed

- Upgraded dependencies to resolve published vulnerabilities (Guava and Lucene); See [#1561](https://github.com/jeremylong/DependencyCheck/issues/1561).

## [Version 3.3.4](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.3.4) (2018-10-28)

### Fixed

- Resolved bug with parsing license information during analysis of Node.js modules.

## [Version 3.3.3](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.3.3) (2018-10-27)

### Changed

- Migrated the NSP Analyzer to use the Node Audit APIs instead; see [#1366](https://github.com/jeremylong/DependencyCheck/issues/1366).
  - Note that the analyzer and configuration was changed to NodeAuditAnalyzer.
  - Configurations for the NSP analyzer have been deprecated and will control the NodeAuditAnalyzer if used; note that the NSP configuration options will be removed in a future release.
- The [dependency-check-gradle](https://github.com/jeremylong/dependency-check-gradle) plugin was updated to include a default scan set
  of ['src/main/resources','src/main/webapp'] and any dependencies contained in these directories will be analyzed. The purpose of this
  enhancement is to enable the RetireJS Analyzer to scan JavaScript files that may be included.

### Fixed

- Resolved **false negative** on Bouncy Castle JAR files; see [#1500](https://github.com/jeremylong/DependencyCheck/issues/1500).
- Resolved **false negatives** that may occur when using the Maven plugin if transitive dependencies of a library in use and is also declared as a primary dependency in a scope that is not used; see [#1512](https://github.com/jeremylong/DependencyCheck/issues/1512).
- Resolved **false negatives** on libraries that contain an update version or timestamp tacked onto the end of the version number; see [#1537](https://github.com/jeremylong/DependencyCheck/issues/1537).
  - The resolution for these false negatives may generate some false positives, please continue to report false positives and the engine can continue to be tuned.
- Fixed bug preventing multiple proxies from being defined for Maven; see [#831](https://github.com/jeremylong/DependencyCheck/issues/831).
- Updated the suppress buttons in the HTML report to generate the XML using the latest suppression schema; see [#489](https://github.com/jeremylong/DependencyCheck/issues/1489).
- Added the `--artifactoryUrl` argument to the CLI - this was missed when the Artifactory Analyzer was previously added; see [#1492](https://github.com/jeremylong/DependencyCheck/issues/1492).
- Updated test cases so that they no longer fail behind a proxy; see [#1493](https://github.com/jeremylong/DependencyCheck/issues/1493).
- Resolved several reported false positives; see [#1504](https://github.com/jeremylong/DependencyCheck/issues/1504), [#1513](https://github.com/jeremylong/DependencyCheck/issues/1513),
  [#1515](https://github.com/jeremylong/DependencyCheck/issues/1515), [#1529](https://github.com/jeremylong/DependencyCheck/issues/1529), [#1535](https://github.com/jeremylong/DependencyCheck/issues/1535),
  and [#1437](https://github.com/jeremylong/DependencyCheck/issues/1437).
- Fixed copy/paste error in JavaDoc; see [#1509](https://github.com/jeremylong/DependencyCheck/issues/1509).

## [Version 3.3.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.3.2) (2018-09-14)

### Fixed

- Gradle plugin was updated to include backward compatibility with gradle < v4.0; see [#95](https://github.com/jeremylong/dependency-check-gradle/issues/95).
- Gradle plugin improved handling of Android project; see [#94](https://github.com/jeremylong/dependency-check-gradle/issues/94)
- CLI used an incorrect key for RetireJS causing the analyzer to not be loaded in some cases; see [#1440](https://github.com/jeremylong/DependencyCheck/issues/1440).
- Resolved failure in the `CentralAnalyzer` when the pom.xml is not available in Central; see [#1439](https://github.com/jeremylong/DependencyCheck/issues/1439).
- Resolved exception when JAR files contain invalid pom.xml files outside of META-INF; see [#1438](https://github.com/jeremylong/DependencyCheck/issues/1438).
- Resolved several reported false positives.

## [Version 3.3.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.3.1) (2018-08-06)

### Changed

- An Nuget Packages.config Analyzer was added; see [#1412](https://github.com/jeremylong/DependencyCheck/issues/1412).

### Fixed

- Fixed error handling with regard to invalid manifest files contained within JAR files; see [#1024](https://github.com/jeremylong/DependencyCheck/issues/1024).
- Fixed parsing of pom.xml files, in some cases a SAX Exception would be thrown; see [#1400](https://github.com/jeremylong/DependencyCheck/issues/1400).
- Fixed bug that caused dependency-check to crash if the temporary directory and data directory were on different drives; see [#1394](https://github.com/jeremylong/DependencyCheck/issues/1394).
- Fixed bug in dependency-check-maven where an aggregate analysis did not scan all files defined in the ScanSet; see [#1421](https://github.com/jeremylong/DependencyCheck/issues/1421).
- Fixed NPE in dependency-check-gradle that occurred when artifacts where included using `implementation files("./lib/some.jar")`; see [#91](https://github.com/jeremylong/dependency-check-gradle/issues/91).

## [Version 3.3.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.3.0) (2018-07-22)

### Changed

- An Artifactory Analyzer was added that can be used to in-place of the Central Analyzer for organizations that use Artifactory.
  - Note, for maven and gradle builds the Artifactory analyzer will not improve the analysis. The information gained by using the Central, Artifactory, or Nexus Analyzers is already obtained from the build system.
- An experimental Retire JS analyzer has been added to analyze client side JavaScript.
  - This utilizes information from the RetireJS repo on github. If you have a proxy that prevents access you will either need to have access granted to https://raw.githubusercontent.com/Retirejs/retire.js/main/repository/jsrepository.json or host the file internally, update the environment variable `analyzer.retirejs.repo.js.ur`, and periodically update the file.
  - This analyzer is considered experimental, but the team expects this to be promoted quickly.
- NuGet dependencies contained in MSBuild files are now included in the scan. See [Issue #1131](https://github.com/jeremylong/DependencyCheck/issues/1131) for more details.
- Cocoapod's Podfile.lock is now analyzed when present. See [PR #1324](https://github.com/jeremylong/DependencyCheck/pull/1324) for more information.

### Fixed

- The dependency-check-gradle plugin can now analyze multi-project android builds. See [PR #09](https://github.com/jeremylong/dependency-check-gradle/pull/90) for more information.
- In some cases extremely large project may cause dependency-check to fail due to the analysis time. Previously, the analysis was capped at 10 minutes; the timeout was increased to 20 minutes and made configurable if this continues to be an issue for some users. See [issue #936](https://github.com/jeremylong/DependencyCheck/issues/936) for more information.
- Some pom.xml files could not be analyzed because they contained a doctype definition. The parser has been enhanced to strip the doctype definitions.
- Fixed issue where, in some cases, temporary files were not correctly cleaned up in Jenkins and gradle builds.
- Fixed issue where, in some cases, files were retrieved from Maven Central using HTTP instead of HTTPS. See [issue #1325](https://github.com/jeremylong/DependencyCheck/issues/1325) for more information.
  - Additionally, a retry count was added when attempting to download pom.xml files during analysis.
- Fixed issue where nodejs dependencies were not correctly analyzed. See [issue #1355](https://github.com/jeremylong/DependencyCheck/issues/1355) for more information.
- Fixed issue where the CWE was not written to the CSV report.
- In addition, general bug fixes, code cleanup, and false positive/negatives updates were made.

## [Version 3.2.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.2.1) (2018-05-28)

### Fixed

- In some cases when using the Maven or Gradle plugins the GAV coordinates were not being added as an Identifier causing suppression rules to fail; this has been resolved (#1298)
- Documentation Update (SCM links in the maven site were broken) (#1297)
- False positive reduction (#1290)
- Enhanced logging output for TLS failures to better assist with debugging (#1269)
- Resolved a Null Pointer Exception (#1296)

## [Version 3.2.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.2.0) (2018-05-21)

### Changed

- Excess white space has been removed from the XML and HTML reports; the JSON report is still pretty printed (a future release will convert this to a configurable option)
- Better error reporting
- Changed to use commons-text instead of commons-lang3 as a portion of commons-lang3 was moved to commonts-text
- Added more flexible suppression rules with the introduction of the `until` attribute (see [#1145](https://github.com/jeremylong/DependencyCheck/issues/1145) and [dependency-suppression.1.2.xsd](https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.2.xsd)

### Fixed

- Unsafe unzip operations ([zip slip](https://github.com/snyk/zip-slip-vulnerability)), as reported by the Snyk Security Research Team, have been corrected. CVE-2018-12036 allows attackers to write to arbitrary files via a crafted archive that holds directory traversal filenames.
- The dependency-check-maven plugin no longer uses the [Central Analyzer](https://jeremylong.github.io/DependencyCheck/analyzers/central-analyzer.html) by default
- Updated dependency-check-maven so that it will not fail when your multi-module build has dependencies that have not yet been built in the reactor (See [#740](https://github.com/jeremylong/DependencyCheck/issues/740))
  - Note if the required dependency has not yet been built in the reactor and the dependency is available in a configured repository dependency-check-maven, as expected, would pull the dependency from the repository for analysis.
- Minor documentation updates
- False positive reduction
- Fixed the Gradle Plugin and Ant Task so that the temp directory is properly cleaned up after execution
- Removed TLSv1 from the list of protocols used by default (See [#1237](https://github.com/jeremylong/DependencyCheck/pull/1237))

## [Version 3.1.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.1.2) (2018-04-02)

### Fixed

- Updated the NVD URLs
- Updated documentation
- Add project references to the JSON and XML report; in aggregate scans using Maven or Gradle the dependencies
  will include a reference to the project/module where they were found
- The configuration option `versionCheckEnabled` was added to Maven to allow users to disable the check for
  new versions of dependency-check; this will be added to gradle plugin, Ant Task, and the CLI in a future release
- The XML and JSON reports were fixed so that the correct version number is displayed see [issue #1109](https://github.com/jeremylong/DependencyCheck/issues/1109)
- The initial database creation time for H2 databases was improved
- Changes made to decrease false positive and false negatives

## [Version 3.1.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.1.1) (2018-01-29)

### Fixed

- Fixed the Central Analyzer to use the updated SHA1 query syntax.
- Reverted change that broke Maven 3.1.0 compatability; Maven 3.1.0 and beyond is once again supported.
- False positive reduction.
- Minor documentation cleanup.

## [Version 3.1.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.1.0) (2018-01-02)

### Changed

- Major enhancements to the Node and NSP analyzer - the analyzers are now considered
  production ready and should be used in combination.
- Added a shutdown hook so that if the update process is interrupted while using an H2
  database the lock files will be properly removed allowing future executions of ODC to
  succeed.
- UNC paths can now be scanned using the CLI.
- Batch updates are now used which may help with the update speed when using some DBMS
  instead of the embedded H2.
- Upgrade Lucene to 5.5.5, the highest version that will allow us to maintain Java 7 support
- Fixed the CSV report output to correctly list all fields.
- Invalid suppression files will now break the build instead of causing ODC to
  skip the usage of the suppression analyzer.
- Fixed bug in Lucene query where LARGE entries in the pom.xml or manifest caused
  the query to break.
- General cleanup, false positive, and false negative reduction.

## [Version 3.0.2](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.0.2) (2017-11-13)

### Fixed

- Updated the query format for the CentralAnalyzer; the old format caused the CentralAnalyzer to fail

## [Version 3.0.1](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.0.1) (2017-10-20)

### Fixed

- Fixed a database connection issue that affected some usages.

## [Version 3.0.0](https://github.com/jeremylong/DependencyCheck/releases/tag/v3.0.0) (2017-10-16)

- Several bug fixes and false positive reduction
  - The 2.x branch introduced several new false positives – but also reduced the false negatives
- Java 9 compatibility update
- Stability issues with the Central Analyzer resolved
  - This comes at a cost of a longer analysis time
- The CSV report now includes the GAV and CPE
- The Hint Analyzer now supports regular expressions
- If show summary is disabled and vulnerable libraries are found that fail the build details are no longer displayed in the console – only that vulnerable libraries were identified
- Resolved issues with threading and multiple connections to the embedded H2 database
  - This allows the Jenkins pipeline, Maven Plugin, etc. to safely run parallel executions of dependency-check
