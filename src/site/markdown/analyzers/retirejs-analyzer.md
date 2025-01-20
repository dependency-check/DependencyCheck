Retire JS Analyzer
==================

OWASP dependency-check includes a Retire JS Analyzer. This analyzer that will scan
JavaScript files and utilize the Retire JS database to identify vulnerable libraries.

The ODC team would like to thank Steve Springett for his intial PR to introduce this analyzer, 
[Philippe Arteau](https://github.com/h3xstream) for the [burp-retire-js plugin](https://github.com/h3xstream/burp-retire-js) which
provides much of the core functionality to use the Retire JS analysis in a Java application,
and lastly [Erlend Oftedal](https://github.com/eoftedal) for building and maintaining [RetireJS](https://github.com/RetireJS/retire.js).

Files Types Scanned: *.js
