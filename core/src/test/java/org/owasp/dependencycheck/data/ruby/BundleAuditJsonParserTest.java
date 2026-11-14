/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2026 OWASP dependency-check contributors. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.ruby;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.ruby.BundleAuditJsonParser.Advisory;
import org.owasp.dependencycheck.data.ruby.BundleAuditJsonParser.Report;
import org.owasp.dependencycheck.data.ruby.BundleAuditJsonParser.GemResult;

import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.time.LocalDate;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BundleAuditJsonParserTest extends BaseTest {

    private Report parse(String resource) throws Exception {
        try (Reader reader = new InputStreamReader(BaseTest.getResourceAsStream(this, resource), UTF_8)) {
            return BundleAuditJsonParser.parse(reader);
        }
    }

    @Test
    void testEmptyResults() throws Exception {
        final Report report = parse("ruby/bundle-audit/empty.json");
        assertEquals("0.9.3", report.getVersion());
        assertTrue(report.getUnpatchedGems().isEmpty());
    }

    @Test
    void testGhsaOnlyAdvisories() throws Exception {
        final List<GemResult> results = parse("ruby/bundle-audit/actionview.json").getUnpatchedGems();
        assertEquals(4, results.size());
        final GemResult r = results.get(0);
        assertEquals("actionview", r.getGem().getName());
        assertEquals("7.2.4", r.getGem().getVersion());
        final Advisory a = r.getAdvisory();
        assertEquals("GHSA-2p2f-4rq4-gjwc", a.getId());
        assertNull(a.getCveId());
        assertNull(a.getOsvdbId());
        assertEquals("GHSA-2p2f-4rq4-gjwc", a.getGhsaId());
        assertEquals("https://github.com/rails/rails/security/advisories/GHSA-2p2f-4rq4-gjwc", a.getUrl());
        assertEquals("Possible XSS vulnerability in Action View text helpers", a.getTitle());
        assertEquals(LocalDate.of(2026, 11, 4), a.getDate());
        assertTrue(a.getDescription().startsWith("### Impact"));
        assertNull(a.getCvssV2Score());
        assertEquals(6.1, a.getCvssV3Score(), 0.0);
        assertNull(a.getCvssV4Score(), "bundler-audit 0.9.3 does not emit cvss_v4");
        assertEquals("medium", a.getCriticality());
        assertTrue(a.getUnaffectedVersions().isEmpty());
        assertEquals(List.of("~> 8.0.5, >= 8.0.5.2", ">= 8.1.4.1"), a.getPatchedVersions());
        for (GemResult each : results) {
            assertTrue(each.getAdvisory().getId().startsWith("GHSA-"), each.getAdvisory().getId());
        }
    }

    @Test
    void testMixedIdentifiersIgnoringInsecureSource() throws Exception {
        // the fixture also contains an insecure_source result, which is ignored
        final List<GemResult> results = parse("ruby/bundle-audit/mixed.json").getUnpatchedGems();
        assertEquals(5, results.size());

        final Advisory noScore = results.get(0).getAdvisory();
        assertEquals("rack", results.get(0).getGem().getName());
        assertEquals("CVE-2015-3225", noScore.getCveId());
        assertEquals("GHSA-rgr4-9jh5-j4j6", noScore.getGhsaId());
        assertNull(noScore.getCvssV2Score());
        assertNull(noScore.getCvssV3Score());
        assertNull(noScore.getCriticality());

        final Advisory v3 = results.get(1).getAdvisory();
        assertEquals("CVE-2018-16471", v3.getCveId());
        assertEquals(6.1, v3.getCvssV3Score(), 0.0);
        assertEquals("medium", v3.getCriticality());

        final Advisory unaffected = results.get(2).getAdvisory();
        assertEquals("CVE-2022-30122", unaffected.getCveId());
        assertEquals(List.of("< 1.2"), unaffected.getUnaffectedVersions());
        assertEquals("high", unaffected.getCriticality());

        final Advisory v2 = results.get(3).getAdvisory();
        assertEquals("activerecord", results.get(3).getGem().getName());
        assertEquals("CVE-2013-3221", v2.getCveId());
        assertEquals(6.4, v2.getCvssV2Score(), 0.0);
        assertNull(v2.getCvssV3Score());

        final Advisory osvdb = results.get(4).getAdvisory();
        assertEquals("redcarpet", results.get(4).getGem().getName());
        assertEquals("OSVDB-120415", osvdb.getId());
        assertNull(osvdb.getCveId());
        assertNull(osvdb.getGhsaId());
        assertEquals("OSVDB-120415", osvdb.getOsvdbId(), "numeric osvdb value is bound as a string");
        assertEquals(List.of(">= 3.2.3"), osvdb.getPatchedVersions());
    }

    @Test
    void testCvssV4IsParsedWhenEmitted() throws Exception {
        // shape produced by bundler-audit after rubysec/bundler-audit#400, plus an unknown future field
        final String json = "{\"version\":\"0.10.0\",\"created_at\":\"2026-11-14 12:42:33 +0000\",\"results\":[{\"type\":\"unpatched_gem\","
                + "\"gem\":{\"name\":\"example\",\"version\":\"1.0.0\"},\"advisory\":{\"path\":\"/x/GHSA-aaaa-bbbb-cccc.yml\",\"id\":\"GHSA-aaaa-bbbb-cccc\","
                + "\"url\":\"https://example.invalid/advisory\",\"title\":\"t\",\"date\":\"2026-01-01\",\"description\":\"d\",\"future_field\":{\"x\":1},"
                + "\"cvss_v2\":null,\"cvss_v3\":null,\"cvss_v4\":8.7,\"cve\":null,\"osvdb\":null,\"ghsa\":\"aaaa-bbbb-cccc\","
                + "\"unaffected_versions\":[],\"patched_versions\":[\">= 1.0.1\"],\"criticality\":\"high\"}}]}";
        final List<GemResult> results = BundleAuditJsonParser.parse(new StringReader(json)).getUnpatchedGems();
        assertEquals(1, results.size());
        final Advisory a = results.get(0).getAdvisory();
        assertNull(a.getCvssV2Score());
        assertNull(a.getCvssV3Score());
        assertEquals(8.7, a.getCvssV4Score(), 0.0);
        assertEquals("high", a.getCriticality());
    }

    @Test
    void testNonJsonOutputIsRejected() {
        assertThrows(AnalysisException.class, () -> BundleAuditJsonParser.parse(new StringReader("Name: actionview\nVersion: 7.2.4\n")));
    }

    @Test
    void testMissingResultsIsRejected() {
        assertThrows(AnalysisException.class, () -> BundleAuditJsonParser.parse(new StringReader("{\"version\":\"0.9.3\"}")));
    }
}
