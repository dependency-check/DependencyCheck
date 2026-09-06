package org.owasp.dependencycheck.data.nodeaudit;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class NpmCliAuditParserTest extends BaseTest {

    private JSONObject loadReport() throws IOException {
        try (InputStream in = BaseTest.getResourceAsStream(this, "nodeaudit/npm-audit-report.json")) {
            return new JSONObject(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    @Test
    void testParse() throws IOException {
        final List<Advisory> advisories = new NpmCliAuditParser().parse(loadReport());

        //two advisory objects for ajv, one for uglify-js; the transitive
        //har-validator entry (string `via`) must not create an advisory
        assertEquals(3, advisories.size());

        final Advisory ajv = findByGhsaId(advisories, "GHSA-v88g-cgmw-v5xw");
        assertEquals("ajv", ajv.getModuleName());
        assertEquals("Prototype Pollution in Ajv", ajv.getTitle());
        assertEquals("Prototype Pollution in Ajv", ajv.getOverview());
        assertEquals("- https://github.com/advisories/GHSA-v88g-cgmw-v5xw", ajv.getReferences());
        assertEquals("moderate", ajv.getSeverity());
        assertEquals("<6.12.3", ajv.getVulnerableVersions());
        assertEquals(List.of("CWE-915", "CWE-1321"), ajv.getCwes());
        assertNotNull(ajv.getCvssV3());
        assertEquals(5.6, ajv.getCvssV3().getCvssData().getBaseScore(), 0.01);
        //the installed version is not part of the report; it is resolved later
        assertNull(ajv.getVersion());

        //a zero score with a null vector must not produce a CVSS record
        final Advisory ajvRedos = findByGhsaId(advisories, "GHSA-2g4f-4pwh-qvx6");
        assertNull(ajvRedos.getCvssV3());

        final Advisory uglify = findByGhsaId(advisories, "GHSA-c9f4-xj24-8jqx");
        assertEquals("uglify-js", uglify.getModuleName());
        assertEquals("high", uglify.getSeverity());
        assertEquals("<2.6.0", uglify.getVulnerableVersions());
        assertEquals(List.of("CWE-1333"), uglify.getCwes());
        assertNotNull(uglify.getCvssV3());
    }

    private static Advisory findByGhsaId(List<Advisory> advisories, String ghsaId) {
        final Advisory advisory = advisories.stream()
                .filter(a -> ghsaId.equals(a.getGhsaId()))
                .findFirst().orElse(null);
        assertNotNull(advisory, "Advisory " + ghsaId + " not found");
        return advisory;
    }

    @Test
    void testParseEmptyReport() {
        final List<Advisory> advisories = new NpmCliAuditParser().parse(
                new JSONObject("{\"auditReportVersion\": 2, \"vulnerabilities\": {}}"));
        assertEquals(0, advisories.size());
    }
}
