[![Maven Central](https://img.shields.io/maven-central/v/org.owasp/dependency-check-maven.svg)](https://mvnrepository.com/artifact/org.owasp/dependency-check-maven) [![Build and Deploy Snapshot](https://github.com/jeremylong/DependencyCheck/actions/workflows/build.yml/badge.svg)](https://github.com/jeremylong/DependencyCheck/actions/workflows/build.yml) [![Coverity Scan Build Status](https://img.shields.io/coverity/scan/1654.svg)](https://scan.coverity.com/projects/dependencycheck) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/6b6021d481dc41a888c5da0d9ecf9494)](https://www.codacy.com/app/jeremylong/DependencyCheck?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=jeremylong/DependencyCheck&amp;utm_campaign=Badge_Grade) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/843/badge)](https://bestpractices.coreinfrastructure.org/projects/843) [![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.txt)

[![Black Hat Arsenal](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/usa/2018.svg?sanitize=true)](https://www.blackhat.com/us-18/arsenal.html#jeremy-long) [![Black Hat Arsenal](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/usa/2015.svg?sanitize=true)](https://www.blackhat.com/us-15/arsenal.html#jeremy-long) [![Black Hat Arsenal](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/usa/2014.svg?sanitize=true)](https://www.blackhat.com/us-14/arsenal.html#Long) [![Black Hat Arsenal](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/usa/2013.svg?sanitize=true)](https://www.blackhat.com/us-13/arsenal.html#Long)

# Dependency-Check

Dependency-Check is a Software Composition Analysis (SCA) tool that attempts to detect publicly disclosed vulnerabilities contained within a project's dependencies. It does this by determining if there is a Common Platform Enumeration (CPE) identifier for a given dependency. If found, it will generate a report linking to the associated CVE entries.

Documentation and links to production binary releases can be found on the [github pages](http://jeremylong.github.io/DependencyCheck/). Additionally, more information about the architecture and ways to extend dependency-check can be found on the [wiki].

## Notice

This product uses the NVD API but is not endorsed or certified by the NVD.


## Breaking Changes in 11.0.0

- Java 11 is now required to run dependency-check 11.0.0 or higher
- H2 database upgrade

    11.0.0 contains breaking changes using the local H2 database. A full download
    of the NVD data will occur. Note that if you are using a shared data directory
    the h2 database file is not compatible with older versions of dependency-check.
    If you run into problems you may need to run a purge:

    - gradle: `./gradlew dependencyCheckPurge`
    - maven: `mvn org.owasp:dependency-check-maven:9.0.0:purge`
    - cli: `dependency-check.sh --purge`

## Mandatory Upgrade Notice

**Upgrading to 10.0.2 or later is mandatory**

Older versions of dependency-check are causing numerous, duplicative requests that
end in processing failures are causing unnecassary load on the NVD API. Dependency-check
10.0.2 uses an updated `User-Agent` header that will allow the NVD to block calls
from the older client.

### NVD API Key Highly Recommended

Dependency-check has moved from using the NVD data-feed to the NVD API.
Users of dependency-check are **highly** encouraged to obtain an NVD API Key; see https://nvd.nist.gov/developers/request-an-api-key
Without an NVD API Key dependency-check's updates will be **extremely slow**.
Please see the documentation for the cli, maven, gradle, or ant integrations on
how to set the NVD API key.

#### The NVD API Key, CI, and Rate Limiting

The NVD API has enforced rate limits. If you are using a single API KEY and
multiple builds occur you could hit the rate limit and receive 403 errors. In
a CI environment one must use a caching strategy.

#### Gradle build Environment

With 9.0.0 users may encounter issues with `NoSuchMethodError` exceptions due to
dependency resolution. If you encounter this issue you will need to pin some of
the transitive dependencies of dependency-check to specific versions. For example:

/buildSrc/build.gradle
```groovy
dependencies {
    constraints {
        // org.owasp.dependencycheck needs at least this version of jackson. Other plugins pull in older versions..
        add("implementation", "com.fasterxml.jackson:jackson-bom:2.16.1")

        // org.owasp.dependencycheck needs these versions. Other plugins pull in older versions..
        add("implementation", "org.apache.commons:commons-lang3:3.14.0")
        add("implementation", "org.apache.commons:commons-text:1.11.0")
    }
}
```

## Requirements

### Java Version

Minimum Java Version: Java 11

### Internet Access

OWASP dependency-check requires access to several externally hosted resources.
For more information see [Internet Access Required](https://jeremylong.github.io/DependencyCheck/data/index.html).

### Build Tools

In order to analyze some technology stacks dependency-check may require other
development tools to be installed. Some of the analysis listed below may be
experimental and require the experimental analyzers to be enabled.

1. To analyze .NET Assemblies the dotnet 8 run time or SDK must be installed.
   - Assemblies targeting other run times can be analyzed - but 8 is required to run the analysis.
2. If analyzing GoLang projects `go` must be installed.
3. The analysis of `Elixir` projects requires `mix_audit`.
4. The analysis of `npm`, `pnpm`, and `yarn` projects requires `npm`, `pnpm`, or `yarn` to be installed.
   - The analysis performed utilize the respective `audit` feature of each.
5. The analysis of Ruby is a wrapper around `bundle-audit`, which must be installed.

## Current Releases

### Jenkins Plugin

For instructions on the use of the Jenkins plugin please see the [OWASP Dependency-Check Plugin page](https://wiki.jenkins-ci.org/display/JENKINS/OWASP+Dependency-Check+Plugin).

### Command Line

More detailed instructions can be found on the
[dependency-check github pages](http://jeremylong.github.io/DependencyCheck/dependency-check-cli/).
The latest CLI can be downloaded from github in the [releases section](https://github.com/jeremylong/DependencyCheck/releases).

Downloading the latest release:
```
$ VERSION=$(curl -s https://jeremylong.github.io/DependencyCheck/current.txt)
$ curl -Ls "https://github.com/jeremylong/DependencyCheck/releases/download/v$VERSION/dependency-check-$VERSION-release.zip" --output dependency-check.zip
```

On *nix
```
$ ./bin/dependency-check.sh -h
$ ./bin/dependency-check.sh --out . --scan [path to jar files to be scanned]
```
On Windows
```
> .\bin\dependency-check.bat -h
> .\bin\dependency-check.bat --out . --scan [path to jar files to be scanned]
```
On Mac with [Homebrew](http://brew.sh)
Note - homebrew users upgrading from 5.x to 6.0.0 will need to run `dependency-check.sh --purge`.
```
$ brew update && brew install dependency-check
$ dependency-check -h
$ dependency-check --out . --scan [path to jar files to be scanned]
```

### Maven Plugin

More detailed instructions can be found on the [dependency-check-maven github pages](http://jeremylong.github.io/DependencyCheck/dependency-check-maven).
By default, the plugin is tied to the `verify` phase (i.e. `mvn verify`). Alternatively,
one can directly invoke the plugin via `mvn org.owasp:dependency-check-maven:check`.

The dependency-check plugin can be configured using the following:

```xml
<project>
    <build>
        <plugins>
            ...
            <plugin>
              <groupId>org.owasp</groupId>
              <artifactId>dependency-check-maven</artifactId>
              <executions>
                  <execution>
                      <goals>
                          <goal>check</goal>
                      </goals>
                  </execution>
              </executions>
            </plugin>
            ...
        </plugins>
        ...
    </build>
    ...
</project>
```

### Gradle Plugin

For instructions on the use of the Gradle Plugin, please see the [dependency-check-gradle github page](http://jeremylong.github.io/DependencyCheck/dependency-check-gradle).

### Ant Task

For instructions on the use of the Ant Task, please see the [dependency-check-ant github page](http://jeremylong.github.io/DependencyCheck/dependency-check-ant).

## Development Prerequisites

For installation to pass, you must have the following components installed:
* Java: `java -version` 11.0
* Maven: `mvn -version` 3.5.0 and higher

Tests cases require:
* dotnet core version 8.0
* Go: `go version` 1.12 and higher
* Ruby [bundler-audit](https://github.com/rubysec/bundler-audit#install)
* [Yarn](https://classic.yarnpkg.com/en/docs/install/)
* [pnpm](https://pnpm.io/installation)

## Development Usage

The following instructions outline how to compile and use the current snapshot. While every intention is to maintain a stable snapshot it is recommended
that the release versions listed above be used.

The repository has some large files due to test resources. The team has tried to clean up the history as much as possible.
However, it is recommended that you perform a shallow clone to save yourself time:

```bash
git clone --depth 1 https://github.com/jeremylong/DependencyCheck.git
```

On *nix
```
$ mvn -s settings.xml install
$ ./cli/target/release/bin/dependency-check.sh -h
$ ./cli/target/release/bin/dependency-check.sh --out . --scan ./src/test/resources
```
On Windows
```
> mvn -s settings.xml install
> .\cli\target\release\bin\dependency-check.bat -h
> .\cli\target\release\bin\dependency-check.bat --out . --scan ./src/test/resources
```

Then load the resulting 'dependency-check-report.html' into your favorite browser.

#### Building without running tests
To speed up your turnaround cycle times, you can also compile without running the tests each time:  
`mvn -s settings.xml install -DskipTests=true`

Please remember to at least run the tests once before opening the PR. :) 

### IntelliJ Idea
To be able to debug your tests in IntelliJ Idea, you can introduce a maven configuration that executes your test and enables debugging with breakpoints etc.  
Basically, you do what´s described in https://www.jetbrains.com/help/idea/work-with-tests-in-maven.html#run_single_test and set the `forkCount` to 0, otherwise debugging won´t work.  

Step by step:  
- `Run -> Edit Configurations`
- `+ (Add new configuration) -> Maven`
- Give the Configuration a name, e.g. `Run tests`
- Choose working directory, e.g. `core`
- In `command line`, enter `-DforkCount=0 -f pom.xml -s ../settings.xml test`
- Press `OK`
- `Run -> Debug`, then choose the newly created run configuration

IntelliJ will now execute the test run for the `core` subproject with enabled debugging. Breakpoints set anywhere in code should work.

#### Only test one function or one class
If you would like to speed up your turnaround cycle times, you can also just test one function or one test class.  
This works by adding `-Dtest=MyTestClass` or `-Dtest=MyTestClass#myTestFunction` to the run configuration. The complete command line in the run configuration then would be:

`-Dtest=MyTestClass#myTestFunction -DforkCount=0 -f pom.xml -s ../settings.xml test`


### Docker

In the following example it is assumed that the source to be checked is in the current working directory and the reports will be written to `$(pwd)/odc-reports`. Persistent data and cache directories are used, allowing you to destroy the container after running.

For Linux:
```sh
#!/bin/sh

DC_VERSION="latest"
DC_DIRECTORY=$HOME/OWASP-Dependency-Check
DC_PROJECT="dependency-check scan: $(pwd)"
DATA_DIRECTORY="$DC_DIRECTORY/data"
CACHE_DIRECTORY="$DC_DIRECTORY/data/cache"

if [ ! -d "$DATA_DIRECTORY" ]; then
    echo "Initially creating persistent directory: $DATA_DIRECTORY"
    mkdir -p "$DATA_DIRECTORY"
fi
if [ ! -d "$CACHE_DIRECTORY" ]; then
    echo "Initially creating persistent directory: $CACHE_DIRECTORY"
    mkdir -p "$CACHE_DIRECTORY"
fi

# Make sure we are using the latest version
docker pull owasp/dependency-check:$DC_VERSION

docker run --rm \
    -e user=$USER \
    -u $(id -u ${USER}):$(id -g ${USER}) \
    --volume $(pwd):/src:z \
    --volume "$DATA_DIRECTORY":/usr/share/dependency-check/data:z \
    --volume $(pwd)/odc-reports:/report:z \
    owasp/dependency-check:$DC_VERSION \
    --scan /src \
    --format "ALL" \
    --project "$DC_PROJECT" \
    --out /report
    # Use suppression like this: (where /src == $pwd)
    # --suppression "/src/security/dependency-check-suppression.xml"
```

For Windows:
```bat
@echo off

set DC_VERSION="latest"
set DC_DIRECTORY=%USERPROFILE%\OWASP-Dependency-Check
SET DC_PROJECT="dependency-check scan: %CD%"
set DATA_DIRECTORY="%DC_DIRECTORY%\data"
set CACHE_DIRECTORY="%DC_DIRECTORY%\data\cache"

IF NOT EXIST %DATA_DIRECTORY% (
    echo Initially creating persistent directory: %DATA_DIRECTORY%
    mkdir %DATA_DIRECTORY%
)
IF NOT EXIST %CACHE_DIRECTORY% (
    echo Initially creating persistent directory: %CACHE_DIRECTORY%
    mkdir %CACHE_DIRECTORY%
)

rem Make sure we are using the latest version
docker pull owasp/dependency-check:%DC_VERSION%

docker run --rm ^
    --volume %CD%:/src ^
    --volume %DATA_DIRECTORY%:/usr/share/dependency-check/data ^
    --volume %CD%/odc-reports:/report ^
    owasp/dependency-check:%DC_VERSION% ^
    --scan /src ^
    --format "ALL" ^
    --project "%DC_PROJECT%" ^
    --out /report
    rem Use suppression like this: (where /src == %CD%)
    rem --suppression "/src/security/dependency-check-suppression.xml"
```

Building From Source
--------------------

To build dependency-check (using Java 11) run the command:

```
mvn -s settings.xml install
```

Running dependency-check on dependency-check
--------------------------------------------

Dependency-check references several vulnerable dependencies that are never used
except as test resources. All of these optional test dependencies are included in
the `test-dependencies` profile. To run dependency-check against itself simple
exclude the `test-dependencies` profile:

```shell
mvn org.owasp:dependency-check-maven:aggregate -P-test-dependencies -DskipProvidedScope=true
```

Building the documentation
--------------------------

The documentation on the [github pages](http://jeremylong.github.io/DependencyCheck/) is generated from this repository:

    mvn -s settings.xml site  site:staging

Once done, point your browser to `./target/staging/index.html`.

Building The Docker Image
-------------------------
To build dependency-check docker image run the command:

```
mvn -s settings.xml install
./build-docker.sh
```

License
-------

Permission to modify and redistribute is granted under the terms of the Apache 2.0 license. See the [LICENSE.txt](https://raw.githubusercontent.com/jeremylong/DependencyCheck/main/LICENSE.txt) file for the full license.

Dependency-Check makes use of several other open source libraries. Please see the [NOTICE.txt][notices] file for more information.

This product uses the NVD API but is not endorsed or certified by the NVD.

Copyright (c) 2012-2024 Jeremy Long. All Rights Reserved.

  [wiki]: https://github.com/jeremylong/DependencyCheck/wiki
  [notices]: https://github.com/jeremylong/DependencyCheck/blob/main/NOTICE.txt
