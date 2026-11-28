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
package org.owasp.dependencycheck.processing;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV3Data;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4Data;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Reference;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.naming.Identifier;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class BundlerAuditProcessorTest extends BaseTest {

    private List<Dependency> process(String resource) throws Exception {
        final Engine engine = mock(Engine.class);
        final Dependency gemLock = new Dependency(BaseTest.getResourceAsFile(this, "ruby/vulnerable/gems/sinatra/Gemfile.lock"));
        try (InputStream in = BaseTest.getResourceAsStream(this, resource);
                BundlerAuditProcessor processor = new BundlerAuditProcessor(gemLock, engine)) {
            processor.setInput(in);
            processor.run();
        }
        final ArgumentCaptor<Dependency> captor = ArgumentCaptor.forClass(Dependency.class);
        verify(engine, org.mockito.Mockito.atLeast(0)).addDependency(captor.capture());
        return captor.getAllValues();
    }

    private static Map<String, Vulnerability> byName(Dependency dependency) {
        return dependency.getVulnerabilities().stream().collect(Collectors.toMap(Vulnerability::getName, Function.identity()));
    }

    @Test
    void testGhsaOnlyAdvisoriesAreReported() throws Exception {
        final List<Dependency> dependencies = process("ruby/bundle-audit/actionview.json");
        assertEquals(1, dependencies.size());
        final Dependency actionview = dependencies.get(0);
        assertEquals("actionview", actionview.getName());
        assertEquals("7.2.4", actionview.getVersion());
        assertEquals("sinatra/Gemfile.lock:actionview", actionview.getDisplayFileName());
        assertEquals("Gemfile.lock", actionview.getFileName());
        assertTrue(actionview.getFilePath().endsWith("ruby/vulnerable/gems/sinatra/Gemfile.lock"));
        assertTrue(actionview.getSoftwareIdentifiers().stream().map(Identifier::getValue)
                .anyMatch("pkg:gem/actionview@7.2.4"::equals), actionview.getSoftwareIdentifiers().toString());

        final Map<String, Vulnerability> vulns = byName(actionview);
        assertEquals(4, vulns.size());
        assertTrue(vulns.keySet().containsAll(List.of("GHSA-2p2f-4rq4-gjwc", "GHSA-68p9-83h6-5wpj",
                "GHSA-rq8q-p985-fjq7", "GHSA-v6rj-xm57-3p59")), vulns.keySet().toString());

        final Vulnerability v = vulns.get("GHSA-2p2f-4rq4-gjwc");
        assertEquals(Vulnerability.Source.BUNDLEAUDIT, v.getSource());
        assertNull(v.getCvssV2());
        assertNotNull(v.getCvssV3());
        assertEquals(6.1, v.getCvssV3().getCvssData().getBaseScore(), 0.0);
        assertEquals(CvssV3Data.SeverityType.MEDIUM, v.getCvssV3().getCvssData().getBaseSeverity());
        assertNull(v.getCvssV4());
        assertNull(v.getUnscoredSeverity());
        assertTrue(v.getDescription().startsWith("Possible XSS vulnerability in Action View text helpers\n\n### Impact"));
        assertTrue(v.getDescription().contains("Patched versions: ~> 8.0.5, >= 8.0.5.2, >= 8.1.4.1"));
        assertEquals(1, v.getReferences().size());
        final Reference ref = v.getReferences().iterator().next();
        assertEquals("bundle-audit", ref.getSource());
        assertEquals("GHSA-2p2f-4rq4-gjwc", ref.getName());
        assertEquals("https://github.com/rails/rails/security/advisories/GHSA-2p2f-4rq4-gjwc", ref.getUrl());
        assertEquals(1, v.getVulnerableSoftware().size());
        assertEquals("cpe:2.3:a:actionview:actionview_project:7.2.4:*:*:*:*:*:*:*", v.getMatchedVulnerableSoftware().toCpe23FS());
    }

    @Test
    void testIdentifierPrecedenceAndScores() throws Exception {
        final List<Dependency> dependencies = process("ruby/bundle-audit/mixed.json");
        final Map<String, Dependency> byGem = dependencies.stream().collect(Collectors.toMap(Dependency::getName, Function.identity()));
        assertEquals(3, byGem.size(), byGem.keySet().toString());

        final Map<String, Vulnerability> rack = byName(byGem.get("rack"));
        assertEquals(3, rack.size(), rack.keySet().toString());

        // CVE wins over GHSA as the name; GHSA becomes a reference; no score -> unscored severity
        final Vulnerability noScore = rack.get("CVE-2015-3225");
        assertNotNull(noScore);
        assertNull(noScore.getCvssV2());
        assertNull(noScore.getCvssV3());
        assertEquals("UNKNOWN", noScore.getUnscoredSeverity());
        assertTrue(noScore.getReferences().stream().anyMatch(r -> "GHSA-rgr4-9jh5-j4j6".equals(r.getName())
                && "https://github.com/advisories/GHSA-rgr4-9jh5-j4j6".equals(r.getUrl())), noScore.getReferences().toString());

        final Vulnerability v3 = rack.get("CVE-2018-16471");
        assertEquals(6.1, v3.getCvssV3().getCvssData().getBaseScore(), 0.0);
        assertNull(v3.getUnscoredSeverity());

        final Vulnerability high = rack.get("CVE-2022-30122");
        assertEquals(7.5, high.getCvssV3().getCvssData().getBaseScore(), 0.0);
        assertEquals(CvssV3Data.SeverityType.HIGH, high.getCvssV3().getCvssData().getBaseSeverity());
        assertTrue(high.getDescription().contains("Unaffected versions: < 1.2"));

        // CVSSv2-only score
        final Vulnerability v2 = byName(byGem.get("activerecord")).get("CVE-2013-3221");
        assertNotNull(v2);
        assertNull(v2.getCvssV3());
        assertEquals(6.4, v2.getCvssV2().getCvssData().getBaseScore(), 0.0);
        assertEquals("MEDIUM", v2.getCvssV2().getCvssData().getBaseSeverity());

        // OSVDB-only advisories are still reported
        final Map<String, Vulnerability> redcarpet = byName(byGem.get("redcarpet"));
        assertEquals(1, redcarpet.size());
        assertNotNull(redcarpet.get("OSVDB-120415"));
        assertEquals("2.2.2", byGem.get("redcarpet").getVersion());
    }

    @Test
    void testAllIdentifiersAttachedWithCvePrecedence() throws Exception {
        final String json = "{\"version\":\"0.9.3\",\"created_at\":\"2026-11-14 12:42:33 +0000\",\"results\":[{\"type\":\"unpatched_gem\","
                + "\"gem\":{\"name\":\"rack\",\"version\":\"1.5.2\"},\"advisory\":{\"path\":\"/x/CVE-2013-0263.yml\",\"id\":\"CVE-2013-0263\","
                + "\"url\":\"https://example.invalid/advisory\",\"title\":\"Timing attack\",\"date\":\"2013-02-07\",\"description\":\"desc\","
                + "\"cvss_v2\":null,\"cvss_v3\":7.5,\"cve\":\"2013-0263\",\"osvdb\":89939,\"ghsa\":\"xxxx-yyyy-zzzz\","
                + "\"unaffected_versions\":[],\"patched_versions\":[\">= 1.5.2\"],\"criticality\":\"high\"}}]}";
        final Engine engine = mock(Engine.class);
        final Dependency gemLock = new Dependency(BaseTest.getResourceAsFile(this, "ruby/vulnerable/gems/sinatra/Gemfile.lock"));
        try (InputStream in = new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));
                BundlerAuditProcessor processor = new BundlerAuditProcessor(gemLock, engine)) {
            processor.setInput(in);
            processor.run();
        }
        final ArgumentCaptor<Dependency> captor = ArgumentCaptor.forClass(Dependency.class);
        verify(engine).addDependency(captor.capture());
        final Map<String, Vulnerability> vulns = byName(captor.getValue());
        assertEquals(1, vulns.size());
        final Vulnerability v = vulns.get("CVE-2013-0263");
        assertNotNull(v, vulns.keySet().toString());
        final Map<String, String> refs = v.getReferences().stream().collect(Collectors.toMap(Reference::getName, r -> String.valueOf(r.getUrl())));
        assertEquals("https://example.invalid/advisory", refs.get("CVE-2013-0263"));
        assertEquals("https://github.com/advisories/GHSA-xxxx-yyyy-zzzz", refs.get("GHSA-xxxx-yyyy-zzzz"));
        assertEquals("null", refs.get("OSVDB-89939"));
        assertEquals(3, refs.size(), refs.toString());
    }

    @Test
    void testCvssV4ScoreIsUsedWhenEmitted() throws Exception {
        // shape produced by bundler-audit after rubysec/bundler-audit#400: cvss_v4 only
        final String json = "{\"version\":\"0.10.0\",\"created_at\":\"2026-11-14 12:42:33 +0000\",\"results\":[{\"type\":\"unpatched_gem\","
                + "\"gem\":{\"name\":\"example\",\"version\":\"1.0.0\"},\"advisory\":{\"path\":\"/x/GHSA-aaaa-bbbb-cccc.yml\",\"id\":\"GHSA-aaaa-bbbb-cccc\","
                + "\"url\":\"https://example.invalid/advisory\",\"title\":\"t\",\"date\":\"2026-01-01\",\"description\":\"d\","
                + "\"cvss_v2\":null,\"cvss_v3\":null,\"cvss_v4\":8.7,\"cve\":null,\"osvdb\":null,\"ghsa\":\"aaaa-bbbb-cccc\","
                + "\"unaffected_versions\":[],\"patched_versions\":[\">= 1.0.1\"],\"criticality\":\"high\"}}]}";
        final Engine engine = mock(Engine.class);
        final Dependency gemLock = new Dependency(BaseTest.getResourceAsFile(this, "ruby/vulnerable/gems/sinatra/Gemfile.lock"));
        try (InputStream in = new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));
                BundlerAuditProcessor processor = new BundlerAuditProcessor(gemLock, engine)) {
            processor.setInput(in);
            processor.run();
        }
        final ArgumentCaptor<Dependency> captor = ArgumentCaptor.forClass(Dependency.class);
        verify(engine).addDependency(captor.capture());
        final Vulnerability v = byName(captor.getValue()).get("GHSA-aaaa-bbbb-cccc");
        assertNotNull(v);
        assertNull(v.getCvssV2());
        assertNull(v.getCvssV3());
        assertNotNull(v.getCvssV4());
        assertEquals(8.7, v.getCvssV4().getCvssData().getBaseScore(), 0.0);
        assertEquals(CvssV4Data.SeverityType.HIGH, v.getCvssV4().getCvssData().getBaseSeverity());
        assertEquals(CvssV4Data.Version._4_0, v.getCvssV4().getCvssData().getVersion());
        assertNull(v.getUnscoredSeverity());
    }

    @Test
    void testNoResultsAddsNoDependencies() throws Exception {
        final Engine engine = mock(Engine.class);
        final Dependency gemLock = new Dependency(BaseTest.getResourceAsFile(this, "ruby/vulnerable/gems/sinatra/Gemfile.lock"));
        try (InputStream in = BaseTest.getResourceAsStream(this, "ruby/bundle-audit/empty.json");
                BundlerAuditProcessor processor = new BundlerAuditProcessor(gemLock, engine)) {
            processor.setInput(in);
            processor.run();
        }
        verify(engine, never()).addDependency(any());
    }

    @Test
    void testTextOutputIsRejected() {
        final Engine engine = mock(Engine.class);
        final Dependency gemLock = new Dependency(BaseTest.getResourceAsFile(this, "ruby/vulnerable/gems/sinatra/Gemfile.lock"));
        final InputStream in = new ByteArrayInputStream("Name: actionview\nVersion: 7.2.4\n".getBytes(StandardCharsets.UTF_8));
        final BundlerAuditProcessor processor = new BundlerAuditProcessor(gemLock, engine);
        processor.setInput(in);
        processor.run();
        assertThrows(AnalysisException.class, processor::close);
    }
}
