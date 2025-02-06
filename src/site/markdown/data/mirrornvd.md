Mirroring External Resources
============================================================
If an organization blocks the servers performing dependency-check scans from
downloading content on the internet they will need to mirror two data sources:
The NVD API and the Retire JS repository.

Creating an offline cache for the NVD API
------------------------------------------------------------

The Open Vulnerability Project's [vuln CLI](https://github.com/dependency-check/Open-Vulnerability-Project/tree/main/vulnz#caching-the-nvd-cve-data)
can be used to create an offline copy of the data obtained from the NVD API.
Then configure dependency-check to use the NVD Datafeed URL.


Mirroring Retire JS Repository
------------------------------------------------------------
The Retire JS Repository is located at:

```
https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json
```

The Retire JS repository can be configured using the `retireJsUrl` configuration option.
See the configuration for the specific dependency-check client used for more information.