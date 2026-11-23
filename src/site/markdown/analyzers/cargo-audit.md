Cargo Audit Analyzer
====================

OWASP dependency-check includes an experimental analyzer that runs
[cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit) on Rust `Cargo.lock`
files and adds the results to the dependency-check report. cargo-audit uses the
[RustSec advisory database](https://rustsec.org).

```shell
$ cargo install cargo-audit --locked
```

By default, the analyzer runs `cargo audit`. To use a different executable, set the path to
`cargo-audit` with `--cargoAudit` (CLI), `cargoAuditPath` (Maven and Ant) or
`analyzer.cargo.audit.path` (properties).

The analyzer runs `cargo audit` from the folder of each `Cargo.lock` file. Thus a
`.cargo/audit.toml` file in that folder applies, for example its list of ignored advisories.

The first audit of a scan fetches the advisory database, and the other audits use that copy.
When auto-update is disabled, the analyzer does not fetch the database. Make sure that the
database at `~/.cargo/advisory-db` is current.

Files Types Scanned: Cargo.lock

Report contents
---------------

- The report includes only the crates that have one or more vulnerabilities. The other crates
  of the `Cargo.lock` file are not in the report or in a generated SBOM.
- The report does not include cargo-audit warnings (unmaintained, unsound or yanked crates).
- When an advisory has a CVE alias that is in the NVD database, the report uses the NVD record
  with a reference to the RustSec advisory. To suppress such a vulnerability, use its CVE ID.
- For other advisories, the severity comes from the RustSec CVSS v3 vector. Advisories without
  a CVSS v3 vector have the severity UNKNOWN.
