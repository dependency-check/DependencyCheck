Ruby Bundle-audit Analyzer
=====================

OWASP dependency-check includes an analyzer that will execute [bundle-audit](https://github.com/rubysec/bundler-audit#readme)
and include the results in the dependency-check report. This is useful for multi-language
projects and merging the results of multiple software composition analysis tools.

**NOTE** - it is important to run `bundle-audit update` occasionally to keep the bundle-audit
database current. ATM - dependency-check does **not** perform the `bundle-audit update` automatically.

dependency-check runs `bundle-audit check --format json` and therefore requires bundler-audit 0.8.0
or later; 0.9.0 or later is recommended so that criticality information is included.

```shell
$ sudo gem install bundler-audit
$ bundle-audit update
```

Files Types Scanned: Gemfile.lock
