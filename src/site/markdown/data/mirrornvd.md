Mirroring External Resources
============================================================
If an organization blocks the servers performing dependency-check scans from
downloading content on the internet they may need to mirror multiple data sources
as documented at [Remote Data Sources](./index.html), however access to data from
the NVD API is currently mandatory.

Mirrors are made available by setting a special URL template in the
`nvdDatafeed`/`nvdDatafeedUrl` configuration. Configuring this URL switches NVD
updates from the REST API to data feeds in the
[NVD JSON 2.0 schema format](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema).
The `{0}` placeholder is replaced with a year or `modified` when dependency-check
retrieves feed data.

Switching to data feeds from the API has some advantages and disadvantages you
should consider:

- ✅ reliability: insulates from API-specific rate limits and availability issues
- ✅ reliability: can be safely cached and proxied via a private centralized
  forward proxy
- ❌ performance: increases data and CPU usage. The entire feed file is downloaded
  for each update and every entry in the dependency-check database is updated
- ❌ support: most options lack a documented SLA
- ❌ complexity: relies on the data feed correctly reflecting all NVD API data
  changes, depending on additional tools or NVD's own proprietary feed creation
  process

Consult your specific dependency-check integration's documentation for
configuration details.

Using dependency-check's own 2.0 data feed mirror
------------------------------------------------------------

Dependency-check [maintains its own mirror/cache](https://github.com/dependency-check/DependencyCheck_Builder/actions/workflows/cache.yml),
built directly from the NVD API using the
[vulnz CLI](https://github.com/jeremylong/open-vulnerability-cli).

If using the dependency-check CLI, set the NVD Datafeed URL to the feed filename
pattern:

```shell
dependency-check.sh --nvdDatafeed \
    'https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/nvdcve-{0}.json.gz'
```

This is updated every 24 hours on a best-effort basis. When the NVD API is
unavailable, it will contain stale data.

Using the NVD 2.0 data feeds
------------------------------------------------------------

Dependency-check can use the
[official NVD 2.0 JSON data feeds](https://nvd.nist.gov/vuln/data-feeds#divJson20Feeds)
instead of the NVD REST API.

If using the dependency-check CLI, set the NVD Datafeed URL to the feed filename
pattern:

```shell
dependency-check.sh --nvdDatafeed \
    'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{0}.json.gz'
```

The official NVD 2.0 data feeds have sometimes been stale for extended periods
(one to two weeks), and during high-load periods can be aggressively rate-limited.
This can lead to extremely slow download speeds, frequent timeouts, and interrupted
downloads. Consider using a caching forward proxy between dependency-check and the
NVD to improve reliability.

Creating an offline cache for the NVD API
------------------------------------------------------------

The Open Vulnerability Project's [vuln CLI](https://github.com/jeremylong/open-vulnerability-cli/blob/main/README.md)
can be used to create an offline copy of the data obtained from the NVD API.
Then configure dependency-check to use the NVD Datafeed URL.
