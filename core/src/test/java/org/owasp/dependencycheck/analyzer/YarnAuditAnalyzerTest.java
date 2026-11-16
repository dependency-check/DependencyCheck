package org.owasp.dependencycheck.analyzer;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3Data;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;

import java.io.File;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

class YarnAuditAnalyzerTest extends BaseTest {

    @Test
    void testGetName() {
        YarnAuditAnalyzer analyzer = new YarnAuditAnalyzer();
        assertThat(analyzer.getName(), is("Yarn Audit Analyzer"));
    }

    @Test
    void testSupportsFiles() {
        YarnAuditAnalyzer analyzer = new YarnAuditAnalyzer();
        assertThat(analyzer.accept(new File("package-lock.json")), is(false));
        assertThat(analyzer.accept(new File("npm-shrinkwrap.json")), is(false));
        assertThat(analyzer.accept(new File("yarn.lock")), is(true));
        assertThat(analyzer.accept(new File("package.json")), is(false));
    }

    /**
     * Regression test for GHSA/`yarn npm audit` advisories only carrying a
     * textual severity (no numeric CVSS score/vector): every parsed
     * {@link Advisory} should now get an estimated CVSSv3 score so that
     * {@code failBuildOnCVSS} and similar numeric thresholds can actually
     * trigger for Yarn Berry findings.
     */
    @Test
    void testParseAdvisoryJsonsSetsEstimatedCvssV3FromSeverity() throws JSONException {
        final JSONObject advisoryJson = new JSONObject();
        advisoryJson.put("value", "brace-expansion");
        final JSONObject children = new JSONObject();
        children.put("ID", 1119441);
        children.put("Issue", "Example advisory");
        children.put("URL", "https://github.com/advisories/GHSA-w5hq-g745-h8pq");
        children.put("Severity", "high");
        children.put("Vulnerable Versions", "<11.1.1");
        children.put("Tree Versions", List.of("3.3.2"));
        advisoryJson.put("children", children);

        final List<Advisory> advisories = YarnAuditAnalyzer.parseAdvisoryJsons(List.of(advisoryJson));

        assertThat(advisories.size(), is(1));
        final Advisory advisory = advisories.get(0);
        assertThat(advisory.getSeverity(), is("high"));
        assertThat(advisory.getCvssV3(), is(org.hamcrest.CoreMatchers.notNullValue()));
        assertThat(advisory.getCvssV3().getCvssData().getBaseScore(), is(8.0));
        assertThat(advisory.getCvssV3().getCvssData().getBaseSeverity(), is(CvssV3Data.SeverityType.HIGH));
    }

    @Test
    void testSeverityToCvssV3MapsKnownSeverities() {
        assertCvssV3(YarnAuditAnalyzer.severityToCvssV3("critical"), 9.5, CvssV3Data.SeverityType.CRITICAL);
        assertCvssV3(YarnAuditAnalyzer.severityToCvssV3("HIGH"), 8.0, CvssV3Data.SeverityType.HIGH);
        assertCvssV3(YarnAuditAnalyzer.severityToCvssV3("moderate"), 5.5, CvssV3Data.SeverityType.MEDIUM);
        assertCvssV3(YarnAuditAnalyzer.severityToCvssV3(" Low "), 2.0, CvssV3Data.SeverityType.LOW);
    }

    @Test
    void testSeverityToCvssV3ReturnsNullForUnknownOrBlankSeverity() {
        assertThat(YarnAuditAnalyzer.severityToCvssV3(null), nullValue());
        assertThat(YarnAuditAnalyzer.severityToCvssV3(""), nullValue());
        assertThat(YarnAuditAnalyzer.severityToCvssV3("not-a-severity"), nullValue());
    }

    private static void assertCvssV3(CvssV3 cvssV3, double expectedScore, CvssV3Data.SeverityType expectedSeverity) {
        assertThat(cvssV3, is(org.hamcrest.CoreMatchers.notNullValue()));
        assertThat(cvssV3.getCvssData().getBaseScore(), is(expectedScore));
        assertThat(cvssV3.getCvssData().getBaseSeverity(), is(expectedSeverity));
    }
}
