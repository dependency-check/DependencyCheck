Mirroring External Resources
============================================================
If an organization blocks the servers performing dependency-check scans from
downloading content on the internet they will need to mirror two data sources:
The NVD API and the Retire JS repository.

Creating an offline cache for the NVD API
------------------------------------------------------------

The Open Vulnerability Project's [vuln CLI](https://github.com/jeremylong/open-vulnerability-cli/blob/main/README.md)
can be used to create an offline copy of the data obtained from the NVD API.
Then configure dependency-check to use the NVD Datafeed URL.
