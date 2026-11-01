package org.owasp.dependencycheck.data.ossindex;

import com.google.common.reflect.TypeToken;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.sonatype.goodies.packageurl.PackageUrl;
import org.sonatype.ossindex.service.api.componentreport.ComponentReport;
import org.sonatype.ossindex.service.api.componentreport.ComponentReportVulnerability;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

class LenientGsonMarshallerTest {

    /**
     * The same type the OSS Index client uses to unmarshal responses.
     */
    private static final TypeToken<List<ComponentReport>> LIST_COMPONENT_REPORT = new TypeToken<>() {};

    private static final String PURL = "pkg:maven/com.mysql/mysql-connector-j@26.7.0";
    private static final String VALID_URI = "https://example.com/component/" + PURL;
    private static final String INVALID_URI = "https://example.com/path with spaces/{and}/braces";

    private final LenientGsonMarshaller marshaller = new LenientGsonMarshaller();

    private static String reportJson(String reportReference, String vulnReference, String externalReferences) {
        return "{"
                + "\"coordinates\":\"" + PURL + "\","
                + "\"description\":\"MySQL Connector/J\","
                + "\"reference\":" + reportReference + ","
                + "\"vulnerabilities\":[{"
                + "  \"id\":\"CVE-2026-0001\","
                + "  \"displayName\":\"CVE-2026-0001\","
                + "  \"title\":\"[CVE-2026-0001] Something\","
                + "  \"cvssScore\":7.5,"
                + "  \"reference\":" + vulnReference + ","
                + "  \"externalReferences\":" + externalReferences
                + "}]"
                + "}";
    }

    private static String quoted(String value) {
        return "\"" + value + "\"";
    }

    private ComponentReport unmarshalSingleReport(String json) throws IOException {
        List<ComponentReport> reports = marshaller.unmarshal("[" + json + "]", LIST_COMPONENT_REPORT);
        assertThat(reports, hasSize(1));
        return reports.get(0);
    }

    @Nested
    class Uris {

        @Test
        void validUrisAreParsedAsNormal() throws IOException {
            String json = reportJson(quoted(VALID_URI), quoted(VALID_URI + "#vuln"), "[" + quoted(VALID_URI + "#ext") + "]");

            ComponentReport report = unmarshalSingleReport(json);

            assertThat(report.getReference(), is(URI.create(VALID_URI)));
            ComponentReportVulnerability vuln = report.getVulnerabilities().get(0);
            assertThat(vuln.getReference(), is(URI.create(VALID_URI + "#vuln")));
            assertThat(vuln.getExternalReferences(), contains(URI.create(VALID_URI + "#ext")));
        }

        @Test
        void invalidComponentReferenceBecomesNullAndRestOfReportSurvives() throws IOException {
            String json = reportJson(quoted(INVALID_URI), quoted(VALID_URI), "[]");

            ComponentReport report = unmarshalSingleReport(json);

            assertThat(report.getReference(), nullValue());
            assertThat(report.getCoordinates(), is(PackageUrl.parse(PURL)));
            assertThat(report.getDescription(), is("MySQL Connector/J"));
            assertThat(report.getVulnerabilities().get(0).getReference(), is(URI.create(VALID_URI)));
        }

        @Test
        void invalidVulnerabilityReferenceBecomesNullAndRestOfVulnerabilitySurvives() throws IOException {
            String json = reportJson(quoted(VALID_URI), quoted(INVALID_URI), "[]");

            ComponentReportVulnerability vuln = unmarshalSingleReport(json).getVulnerabilities().get(0);

            assertThat(vuln.getReference(), nullValue());
            assertThat(vuln.getId(), is("CVE-2026-0001"));
            assertThat(vuln.getCvssScore(), is(7.5f));
        }

        @Test
        void invalidExternalReferenceBecomesNullEntryWhileValidOnesAreKept() throws IOException {
            String json = reportJson(quoted(VALID_URI), quoted(VALID_URI),
                    "[" + quoted(VALID_URI + "#one") + "," + quoted(INVALID_URI) + "," + quoted(VALID_URI + "#two") + "]");

            ComponentReportVulnerability vuln = unmarshalSingleReport(json).getVulnerabilities().get(0);

            assertThat(vuln.getExternalReferences(), contains(URI.create(VALID_URI + "#one"), null, URI.create(VALID_URI + "#two")));
        }

        @Test
        void jsonNullUrisRemainNull() throws IOException {
            String json = reportJson("null", "null", "null");

            ComponentReport report = unmarshalSingleReport(json);

            assertThat(report.getReference(), nullValue());
            assertThat(report.getVulnerabilities().get(0).getReference(), nullValue());
            // ComponentReportVulnerability exposes an empty list rather than null for missing external references
            assertThat(report.getVulnerabilities().get(0).getExternalReferences(), is(empty()));
        }

        @Test
        void leniencyAppliesToEveryUnmarshalOverload() throws IOException {
            String json = "{\"coordinates\":\"" + PURL + "\",\"reference\":" + quoted(INVALID_URI) + "}";
            String listJson = "[" + json + "]";

            assertThat(marshaller.unmarshal(json, ComponentReport.class).getReference(), nullValue());
            assertThat(marshaller.unmarshal(new StringReader(json), ComponentReport.class).getReference(), nullValue());
            assertThat(marshaller.unmarshal(listJson, LIST_COMPONENT_REPORT).get(0).getReference(), nullValue());
            assertThat(marshaller.unmarshal(new StringReader(listJson), LIST_COMPONENT_REPORT).get(0).getReference(), nullValue());
        }

        @Test
        void urisAreMarshalledAsStrings() throws IOException {
            ComponentReport report = new ComponentReport();
            report.setReference(URI.create(VALID_URI));

            String json = marshaller.marshal(report);

            assertThat(json, containsString("\"reference\":\"" + VALID_URI + "\""));
            assertThat(marshaller.unmarshal(json, ComponentReport.class).getReference(), is(URI.create(VALID_URI)));
        }
    }

    @Test
    void packageUrlRoundTripsThroughMarshalAndUnmarshal() throws IOException {
        ComponentReport original = new ComponentReport();
        original.setCoordinates(PackageUrl.parse(PURL));

        ComponentReport copy = marshaller.unmarshal(marshaller.marshal(original), ComponentReport.class);

        assertThat(copy.getCoordinates(), is(original.getCoordinates()));
    }
}
