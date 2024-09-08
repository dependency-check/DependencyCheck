File Type Analyzers
====================
OWASP dependency-check contains several file type analyzers that are used
to extract identification information from the files analyzed.

| Analyzer | File Types Scanned | Analysis Method |
| -------- | ------------------ | --------------- |
| [Archive](./archive-analyzer.html) | Zip archive format (\*.zip, \*.ear, \*.war, \*.jar, \*.sar, \*.apk, \*.nupkg); Tape Archive Format (\*.tar); Gzip format (\*.gz, \*.tgz); Bzip2 format (\*.bz2, \*.tbz2); RPM format (\*.rpm) | Extracts archive contents, then scans contents with all available analyzers. |
| [Assembly](./assembly-analyzer.html) | .NET Assemblies (\*.exe, \*.dll) | Uses [GrokAssembly.exe](https://github.com/colezlaw/GrokAssembly); requires the dotnet core 8.0 runtime to be installed. |
| [Jar](./jar-analyzer.html) | Java archive files (\*.jar); Web application archive (\*.war) | Examines archive manifest metadata, and Maven Project Object Model files (pom.xml). |
| [RetireJS](./retirejs-analyzer.html) | JavaScript files | Analyzes JavaScript files using the [RetireJS](https://github.com/RetireJS/retire.js) database. |
| [Node.js](./nodejs.html) | NPM package specification files (package.json) | Parses the package.json to gather a bill-of-materials for a Node JS project. |
| [Node Audit](./node-audit-analyzer.html) | Uses the `npm audit` APIs to report on known vulnerable node.js libraries. This analyzer requires an Internet connection. |
| [Nugetconf](./nugetconf-analyzer.html) | Nuget packages.config file | Uses XPath to parse specification XML. |
| [Nuspec](./nuspec-analyzer.html) | Nuget package specification file (\*.nuspec) | Uses XPath to parse specification XML. |
| [OpenSSL](./openssl.html) | OpenSSL Version Source Header File (opensslv.h) | Regex parse of the OPENSSL_VERSION_NUMBER macro definition. |
| [OSS Index](./oss-index-analyzer.html) | Uses the [OSS Index](https://ossindex.sonatype.org/) APIs to report on vulnerabilities not found in the NVD. This analyzer requires an Internet connection. |
| [Ruby bundler&#8209;audit](./bundle-audit.html) | Ruby `Gemfile.lock` files | Executes bundle-audit and incorporates the results into the dependency-check report. |

Experimental Analyzers
----------------------
The following analyzers can be enabled by enabling the _experimental_ configuration
option; see the documentation for the CLI, Ant, Maven, etc. for more information.
These analyzers are considered experimental due to the higher false positive and
false negative rates. Even though these are marked as experimental
several teams have found them useful in their current state.

| Analyzer | File Types Scanned | Analysis Method |
| -------- | ------------------ | --------------- |
| [Autoconf](./autoconf.html) | Autoconf project configuration files (configure, configure.in, configure.ac) | [Regex](https://en.wikipedia.org/wiki/Regular_expression) scan for AC_INIT metadata, including in generated configuration script. |
| [CMake](./cmake.html) | CMake project files (CMakeLists.txt) and scripts (\*.cmake) | Regex scan for project initialization and version setting commands. |
| [CocoaPods](./cocoapods.html) | CocoaPods `.podspec` files | Extracts dependency information from specification file. |
| [Carthage](./carthage.html) | Carthage `Cartfile.resolved` files | Extracts dependency information from specification file. |
| [Composer Lock](./composer-lock.html) | PHP [Composer](http://getcomposer.org) Lock files (composer.lock) | Parses PHP [Composer](http://getcomposer.org) lock files for exact versions of dependencies. |
| [CPAN File](./cpanfile.html) | Perl [cpanfile](https://metacpan.org/pod/distribution/Module-CPANfile/lib/cpanfile.pod) Lock files (composer.lock) | Parses Perl [cpanfile](https://metacpan.org/pod/distribution/Module-CPANfile/lib/cpanfile.pod) files for dependencies. |
| [Dart](./dart.html) | `pubspec.yaml`, `pubspec.lock` | Extracts dependency information from specification files. |
| [Go lang mod](./golang-mod.html) | `go.mod`| Uses `go mod` to determine exactly which dependencies are used. |
| [Go lang dep](./golang-dep.html) | `Gopkg.lock` | Analyzes the lock file directly to parse dependency information. |
| [PE Analyzer](./pe-analyzer.html) | `PE DLL and EXE` | Analyzes the PE Headers to obtain dependency information. |
| [Python](./python.html) | Python source files (\*.py); Package metadata files (PKG-INFO, METADATA); Package Distribution Files (\*.whl, \*.egg, \*.zip) | Regex scan of Python source files for setuptools metadata; Parse RFC822 header format for metadata in all other artifacts. |
| [Pip](./pip.html) | Python Pip requirements.txt files | Regex scan of requirements.txt. |
| [Ruby Gemspec](./ruby-gemspec.html) | Ruby makefiles (Rakefile); Ruby Gemspec files (\*.gemspec) | Regex scan Gemspec initialization blocks for metadata. |
| [SWIFT](./swift.html) | SWIFT Package Manager's `Package.swift` | Extracts dependency information from swift package file. |
