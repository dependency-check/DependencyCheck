package org.owasp.dependencycheck.analyzer;

import com.h3xstream.retirejs.repo.JsLibrary;
import com.h3xstream.retirejs.repo.JsLibraryResult;
import com.h3xstream.retirejs.repo.JsVulnerability;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Reference;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.owasp.dependencycheck.analyzer.RetireJsLibrary.KnownIdentifierTypes.CVE;
import static org.owasp.dependencycheck.analyzer.RetireJsLibrary.KnownIdentifierTypes.GITHUB_SECURITY_ADVISORY;
import static org.owasp.dependencycheck.analyzer.RetireJsLibrary.KnownIdentifierTypes.SUMMARY;
import static org.owasp.dependencycheck.dependency.Vulnerability.Source.NVD;
import static org.owasp.dependencycheck.dependency.Vulnerability.Source.RETIREJS;

class RetireJsLibraryTest {

    private static final String TEST_LIB = "vuln-lib";
    private static final String TEST_VERSION = "1.1";
    private static final String TEST_INFO_LINK = "https://github.com/some-link";

    @Test
    void shouldConvertBasicFields() throws Exception {
        RetireJsLibrary retireJsLibrary = RetireJsLibrary.adapt(testResultFor(Collections.emptyMap()));

        assertThat(retireJsLibrary.libraryName(), is(TEST_LIB));
        assertThat(retireJsLibrary.version(), is(TEST_VERSION));
        assertThat(retireJsLibrary.identifier(), is(new PurlIdentifier("javascript", TEST_LIB, TEST_VERSION, Confidence.HIGHEST)));

        Vulnerability vuln = assertHasSingleRetireJsVuln(retireJsLibrary, cve -> null);
        assertThat(vuln.getName(), is("Vulnerability in vuln-lib")); // fallback name when no identifiers exist
        assertThat(vuln.getSource(), is(RETIREJS));
        assertThat(vuln.getUnscoredSeverity(), is("medium"));
        assertThat(vuln.getDescription(), nullValue());
        assertThat(vuln.getReferences(), containsInAnyOrder(new Reference(TEST_INFO_LINK, "info", TEST_INFO_LINK)));
    }

    @Test
    void shouldParseNonUrlInfoReferences() {
        JsLibraryResult result = testResultFor(Collections.emptyMap());
        JsVulnerability prev = result.getVuln();
        result.setVuln(new JsVulnerability(prev.getAtOrAbove(), prev.getBelow(), List.of("Some non-url info", TEST_INFO_LINK), prev.getIdentifiers(), prev.getSeverity()));
        RetireJsLibrary retireJsLibrary = RetireJsLibrary.adapt(result);

        Vulnerability vuln = assertHasSingleRetireJsVuln(retireJsLibrary, cve -> null);

        assertThat(vuln.getReferences(), containsInAnyOrder(
                new Reference(TEST_INFO_LINK, "info", TEST_INFO_LINK),
                new Reference("Some non-url info", "info", null))
        );
    }

    @Nested
    class SummaryIdentifiers {
        @Test
        void summaryIdentifierUsedAsNameWhenNoOtherIdentifiersExist() {
            RetireJsLibrary retireJsLibrary = RetireJsLibrary.adapt(testResultFor(Map.of(SUMMARY, List.of("XSS in lib"))));
            Vulnerability vuln = assertHasSingleRetireJsVuln(retireJsLibrary, cve -> null);
            assertThat(vuln.getName(), is("XSS in lib"));
            assertThat(vuln.getDescription(), is("XSS in lib"));
        }

        @Test
        void summaryIdentifierIgnoredForNameIfTooLong() {
            String longSummary = "s".repeat(101);
            RetireJsLibrary retireJsLibrary = RetireJsLibrary.adapt(testResultFor(Map.of(SUMMARY, List.of(longSummary))));
            Vulnerability vuln = assertHasSingleRetireJsVuln(retireJsLibrary, cve -> null);
            assertThat(vuln.getName(), is("Vulnerability in vuln-lib")); // fallback name when no identifiers exist
            assertThat(vuln.getDescription(), is(longSummary));
        }

        @Test
        void summaryIdentifierIgnoredForNameIfMultiLine() {
            String multilineSummary = "multiple\nlines";
            RetireJsLibrary retireJsLibrary = RetireJsLibrary.adapt(testResultFor(Map.of(SUMMARY, List.of(multilineSummary))));
            Vulnerability vuln = assertHasSingleRetireJsVuln(retireJsLibrary, cve -> null);
            assertThat(vuln.getName(), is("Vulnerability in vuln-lib")); // fallback name when no identifiers exist
            assertThat(vuln.getDescription(), is(multilineSummary));
        }
    }

    @Nested
    class IdentifierPreference {
        @Test
        void cveIdentifierShouldFallbackToRetireJsDetails() {
            RetireJsLibrary retireJsLibrary = RetireJsLibrary.adapt(testResultFor(Map.of(CVE, List.of("CVE-123"))));

            Vulnerability vuln = assertHasSingleRetireJsVuln(retireJsLibrary, cve -> null);
            assertThat(vuln.getName(), is("CVE-123"));
            assertThat(vuln.getSource(), is(RETIREJS));
            assertThat(vuln.getUnscoredSeverity(), is("medium"));
            assertThat(vuln.getDescription(), nullValue());
        }

        @Test
        void cveIdentifierShouldPreferNvdData() {
            RetireJsLibrary retireJsLibrary = RetireJsLibrary.adapt(testResultFor(Map.of(CVE, List.of("CVE-123"))));

            Vulnerability vuln = assertHasSingleRetireJsVuln(retireJsLibrary, this::existingNvdVuln);
            assertThat(vuln.getName(), is("CVE-123"));
            assertThat(vuln.getSource(), is(NVD));
            assertThat(vuln.getUnscoredSeverity(), nullValue());
            assertThat(vuln.getDescription(), is("Existing NVD vuln"));
        }

        @Test
        void cveIdentifiersShouldAllowMultiple() {
            RetireJsLibrary retireJsLibrary = RetireJsLibrary.adapt(testResultFor(Map.of(CVE, List.of("CVE-123", "CVE-456"))));

            List<Vulnerability> vulnerabilities = retireJsLibrary.vulnerabilities(cve -> "CVE-123".equals(cve) ? existingNvdVuln(cve) : null);
            assertThat(vulnerabilities, hasSize(2));
            Vulnerability vuln = vulnerabilities.get(0);
            assertThat(vuln.getName(), is("CVE-123"));
            assertThat(vuln.getSource(), is(NVD));
            assertThat(vuln.getUnscoredSeverity(), nullValue());
            assertThat(vuln.getDescription(), is("Existing NVD vuln"));

            Vulnerability vuln2 = vulnerabilities.get(1);
            assertThat(vuln2.getName(), is("CVE-456"));
            assertThat(vuln2.getSource(), is(RETIREJS));
            assertThat(vuln2.getUnscoredSeverity(), is("medium"));
            assertThat(vuln2.getDescription(), nullValue());
        }

        @Test
        void cveIdentifierShouldBePreferredWithReferencesFallback() {
            RetireJsLibrary retireJsLibrary = RetireJsLibrary.adapt(testResultFor(Map.of(
                    CVE, List.of("CVE-123"),
                    GITHUB_SECURITY_ADVISORY, List.of("GHSA-1234") // Ignored
            )));
            Vulnerability vuln = assertHasSingleRetireJsVuln(retireJsLibrary, cve -> null);
            assertThat(vuln.getName(), is("CVE-123"));

            assertThat(vuln.getReferences(), containsInAnyOrder(
                    new Reference(TEST_INFO_LINK, "info", TEST_INFO_LINK),
                    new Reference("GHSA-1234", "ghsaId", null)
            ));
        }

        @Test
        void cveIdentifierShouldBePreferredWithReferencesIgnoredIfInNvd() {
            RetireJsLibrary retireJsLibrary = RetireJsLibrary.adapt(testResultFor(Map.of(
                    CVE, List.of("CVE-123"),
                    GITHUB_SECURITY_ADVISORY, List.of("GHSA-1234") // Ignored
            )));
            Vulnerability vuln = assertHasSingleRetireJsVuln(retireJsLibrary, this::existingNvdVuln);
            assertThat(vuln.getName(), is("CVE-123"));

            assertThat(vuln.getReferences(), containsInAnyOrder(
                    new Reference(TEST_INFO_LINK, "info", TEST_INFO_LINK)
            ));
        }

        @ParameterizedTest
        @MethodSource("org.owasp.dependencycheck.analyzer.RetireJsLibraryTest#alternateIdentifierTypes")
        void ghsaIdShouldBePreferredToKnownNames(String alternateIdentifierType) {
            RetireJsLibrary retireJsLibrary = RetireJsLibrary.adapt(testResultFor(Map.of(
                    GITHUB_SECURITY_ADVISORY, List.of("GHSA-1234"),
                    alternateIdentifierType, List.of("alt-id-1")
            )));
            Vulnerability vuln = assertHasSingleRetireJsVuln(retireJsLibrary, this::existingNvdVuln);
            assertThat(vuln.getName(), is("GHSA-1234"));

            assertThat(vuln.getReferences(), containsInAnyOrder(
                    new Reference(TEST_INFO_LINK, "info", TEST_INFO_LINK),
                    new Reference("GHSA-1234", "ghsaId", null),
                    new Reference("alt-id-1", alternateIdentifierType, null)
            ));
        }

        @ParameterizedTest
        @MethodSource("org.owasp.dependencycheck.analyzer.RetireJsLibraryTest#alternateIdentifierTypes")
        void otherKnownIdentifiersCanBeUsedAsName(String alternateIdentifierType) {
            RetireJsLibrary retireJsLibrary = RetireJsLibrary.adapt(testResultFor(Map.of(
                    alternateIdentifierType, List.of("alt-id-1")
            )));
            Vulnerability vuln = assertHasSingleRetireJsVuln(retireJsLibrary, this::existingNvdVuln);
            assertThat(vuln.getName(), is("vuln-lib " + alternateIdentifierType + ": alt-id-1"));

            assertThat(vuln.getReferences(), containsInAnyOrder(
                    new Reference(TEST_INFO_LINK, "info", TEST_INFO_LINK),
                    new Reference("alt-id-1", alternateIdentifierType, null)
            ));
        }

        private @NonNull Vulnerability existingNvdVuln(String cve) {
            Vulnerability nvdVuln = new Vulnerability(cve);
            nvdVuln.setSource(NVD);
            nvdVuln.setDescription("Existing NVD vuln");
            return nvdVuln;
        }
    }

    static List<String> alternateIdentifierTypes() {
        return org.owasp.dependencycheck.analyzer.RetireJsLibrary.KnownIdentifierTypes.SECONDARY_NAME_TYPES;
    }

    private static Vulnerability assertHasSingleRetireJsVuln(RetireJsLibrary retireJsLibrary, RetireJsLibrary.KnownCveProvider cveLookup) {
        List<Vulnerability> vulnerabilities = retireJsLibrary.vulnerabilities(cveLookup);
        assertThat(vulnerabilities, hasSize(1));
        return vulnerabilities.get(0);
    }

    private JsLibraryResult testResultFor(Map<String, List<String>> identifiers) {
        JsLibrary lib = new JsLibrary();
        lib.setName(TEST_LIB);
        JsVulnerability vuln = new JsVulnerability("1.0", "2.0", List.of(TEST_INFO_LINK), identifiers, "medium");
        return new JsLibraryResult(lib, vuln, TEST_VERSION, "", "");
    }
}