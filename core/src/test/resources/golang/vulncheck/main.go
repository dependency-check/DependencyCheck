package main

import (
	"fmt"

	"golang.org/x/text/language"
)

// Calls into golang.org/x/text/language.Parse, which in v0.3.5 is affected by
// GO-2021-0113 (CVE-2021-38561) - so govulncheck reports a reachable ("called")
// finding for this module. Used by GolangVulncheckAnalyzerIT.
func main() {
	tag, err := language.Parse("en-US")
	if err != nil {
		panic(err)
	}
	fmt.Println(tag)
}
