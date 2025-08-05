Python Analyzer
==============

*Experimental*: This analyzer is considered experimental. While this analyzer may 
be useful and provide valid results more testing must be completed to ensure that
the false negative/false positive rates are acceptable. 

OWASP dependency-check includes an analyzer that will scan Python artifacts.
The analyzer(s) will collect as much information it can about the Python
artifacts. The information collected is internally referred to as evidence and
is grouped into vendor, product, and version buckets. Other analyzers later
use this evidence to identify any Common Platform Enumeration (CPE)
identifiers that apply.

Files Types Scanned: py, whl, egg, zip, PKG-INFO, and METADATA

Analyzing packages built with `poetry build`
--------------------------------------------

Note that running `dependency-check` on Python packages built with
[Poetry](https://python-poetry.org)'s
[`poetry build`](https://python-poetry.org/docs/cli/#build) command
**may throw an error**:

`[ERROR] Python 'pyproject.toml' found and there is not a 'poetry.lock' or
'requirements.txt' - analysis will be incomplete`

This is **known behaviour** (see
[#6356](https://github.com/dependency-check/DependencyCheck/issues/6356))
and is due to the analyzer analyzing the contents of the tarball
that has been built (in `dist/<package>-<version>.tar.gz` if built using Poetry
defaults). As per [PEP 517](https://peps.python.org/pep-0517/), the tarball
contains the `pyproject.toml` manifest, but not the `poetry.lock` file
that [freezes](https://python-poetry.org/docs/cli/#lock) dependencies at
the versions used to build the project.

To **circumvent this error**, exclude the tarball or the whole build target
directory by running `dependency-check` with `--exclude "dist/**"`.

***WARNING:*** This will not analyze the build artifact itself, but only the lock
file. If dependencies have diverged between the two artifacts - e.g., after
updating a depdendency and locking it without building again - the dependencies
in the build artifact may be affected by vulnerabilities that will go undetected!
