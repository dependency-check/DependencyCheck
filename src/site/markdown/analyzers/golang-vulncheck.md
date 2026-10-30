Golang Vulncheck Analyzer
==============

*v1 of the scanner*: This is the first version (v1) of the govulncheck-based scanner
integration. It leverages govulncheck's curated Go vulnerability database and
call-graph reachability analysis to keep false positive and false negative rates low.

OWASP dependency-check includes an analyzer that runs the Go team's
[govulncheck](https://go.dev/doc/security/vuln) tool against a Go module and reports
the vulnerabilities it finds. Unlike the [Golang Mod Analyzer](./golang-mod.html),
which relies on CPE matching against the NVD, govulncheck consults the curated Go
vulnerability database and performs reachability (call-graph) analysis, so it reports
primarily the vulnerabilities that are actually reachable from the scanned code.
This substantially reduces the false positive and false negative rates for Go modules.

For each reported vulnerability the analyzer adds a synthetic dependency for the
vulnerable Go module and attaches the vulnerability to it. When a govulncheck advisory
carries a CVE alias that dependency-check already knows about, the existing record is
reused so the finding is de-duplicated against the other data sources.

This analyzer requires that both `go` and `govulncheck` are installed and available.
`govulncheck` can be installed with:

```
go install golang.org/x/vuln/cmd/govulncheck@latest
```

The analyzer is disabled by default (in addition to requiring the _experimental_
option). It may be enabled and the path to `govulncheck` configured; see the
documentation for the CLI, Ant, Maven, etc. for the relevant configuration options
(`analyzer.golang.vulncheck.enabled` and `analyzer.golang.vulncheck.path`).

File names scanned: go.mod
