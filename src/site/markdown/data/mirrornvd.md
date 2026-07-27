Mirroring External Resources
============================================================
If an organization blocks the servers performing dependency-check scans from
downloading content on the internet they will need to mirror two data sources:
The NVD API and the Retire JS repository.

Using the NVD 2.0 data feeds
------------------------------------------------------------

Dependency-check can use the official NVD 2.0 JSON data feeds instead of the
NVD REST API. Set the NVD Datafeed URL to the feed filename pattern:

```shell
dependency-check.sh --nvdDatafeed \
    'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{0}.json.gz'
```

For the Maven plugin, use the equivalent configuration:

```xml
<configuration>
    <nvdDatafeedUrl>https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{0}.json.gz</nvdDatafeedUrl>
</configuration>
```

The `{0}` placeholder is replaced with a year or `modified` when
dependency-check retrieves feed data. Configuring this URL switches NVD updates
from the REST API to the data feeds.

Creating an offline cache for the NVD API
------------------------------------------------------------

The Open Vulnerability Project's [vuln CLI](https://github.com/jeremylong/open-vulnerability-cli/blob/main/README.md)
can be used to create an offline copy of the data obtained from the NVD API.
Then configure dependency-check to use the NVD Datafeed URL.
