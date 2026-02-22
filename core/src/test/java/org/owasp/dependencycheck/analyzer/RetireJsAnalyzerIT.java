/*
 * This file is part of dependency-check-cofre.
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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.update.RetireJSDataSource;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RetireJsAnalyzerIT extends BaseDBTestCase {

    private RetireJsAnalyzer analyzer;
    private Engine engine;

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        engine = new Engine(getSettings());
        engine.openDatabase(true, true);
        RetireJSDataSource ds = new RetireJSDataSource();
        ds.update(engine);
        analyzer = new RetireJsAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize(getSettings());
        analyzer.prepare(engine);
    }

    @AfterEach
    @Override
    public void tearDown() throws Exception {
        analyzer.close();
        engine.close();
        super.tearDown();
    }

    @Test
    void testGetName() {
        assertThat(analyzer.getName(), is("RetireJS Analyzer"));
    }

    /**
     * Test of getSupportedExtensions method.
     */
    @Test
    void testAcceptSupportedExtensions() {
        analyzer.setEnabled(true);
        String[] files = {"test.js", "test.min.js"};
        for (String name : files) {
            assertTrue(analyzer.accept(new File(name)), name);
        }
    }

    /**
     * Test of getAnalysisPhase method.
     */
    @Test
    void testGetAnalysisPhase() {
        AnalysisPhase expResult = AnalysisPhase.FINDING_ANALYSIS;
        AnalysisPhase result = analyzer.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method.
     */
    @Test
    void testGetAnalyzerEnabledSettingKey() {
        String expResult = Settings.KEYS.ANALYZER_RETIREJS_ENABLED;
        String result = analyzer.getAnalyzerEnabledSettingKey();
        assertEquals(expResult, result);
    }

    /**
     * Test of inspect method.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    void testJquery() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "javascript/jquery-1.6.2.js");
        Dependency dependency = new Dependency(file);
        analyzer.analyze(dependency, engine);

        assertEquals("jquery", dependency.getName());
        assertEquals("1.6.2", dependency.getVersion());

        assertEquals(1, dependency.getEvidence(EvidenceType.PRODUCT).size());
        Evidence product = dependency.getEvidence(EvidenceType.PRODUCT).iterator().next();
        assertEquals("name", product.getName());
        assertEquals("jquery", product.getValue());

        assertEquals(1, dependency.getEvidence(EvidenceType.VERSION).size());
        Evidence version = dependency.getEvidence(EvidenceType.VERSION).iterator().next();
        assertEquals("version", version.getName());
        assertEquals("1.6.2", version.getValue());

        assertTrue(dependency.getVulnerabilities().size() >= 3);
        assertTrue(dependency.getVulnerabilities().contains(new Vulnerability("CVE-2015-9251")));
        assertTrue(dependency.getVulnerabilities().contains(new Vulnerability("CVE-2011-4969")));
        assertTrue(dependency.getVulnerabilities().contains(new Vulnerability("CVE-2012-6708")));
    }

    /**
     * Test of inspect method.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    void testAngular() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "javascript/angular.safe.js");
        Dependency dependency = new Dependency(file);
        analyzer.analyze(dependency, engine);

        assertEquals("angularjs", dependency.getName());
        assertEquals("1.2.27", dependency.getVersion());

        assertEquals(1, dependency.getEvidence(EvidenceType.PRODUCT).size());
        Evidence product = dependency.getEvidence(EvidenceType.PRODUCT).iterator().next();
        assertEquals("name", product.getName());
        assertEquals("angularjs", product.getValue());

        assertEquals(1, dependency.getEvidence(EvidenceType.VERSION).size());
        Evidence version = dependency.getEvidence(EvidenceType.VERSION).iterator().next();
        assertEquals("version", version.getName());
        assertEquals("1.2.27", version.getValue());

        assertTrue(dependency.getVulnerabilities().size() >= 6,
                "At leats 6 vulnerabilities should be detected");
        assertTrue(dependency.getVulnerabilities().contains(new Vulnerability("Universal CSP bypass via add-on in Firefox")));
        assertTrue(dependency.getVulnerabilities().contains(new Vulnerability("XSS in $sanitize in Safari/Firefox")));
        assertTrue(dependency.getVulnerabilities().contains(new Vulnerability("DOS in $sanitize")));
        assertTrue(dependency.getVulnerabilities().contains(new Vulnerability("The attribute usemap can be used as a security exploit")));
    }

    /**
     * Test of inspect method.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    void testEmber() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "javascript/ember.js");
        Dependency dependency = new Dependency(file);
        analyzer.analyze(dependency, engine);

        assertEquals("ember", dependency.getName());
        assertEquals("1.3.0", dependency.getVersion());

        assertEquals(1, dependency.getEvidence(EvidenceType.PRODUCT).size());
        Evidence product = dependency.getEvidence(EvidenceType.PRODUCT).iterator().next();
        assertEquals("name", product.getName());
        assertEquals("ember", product.getValue());

        assertEquals(1, dependency.getEvidence(EvidenceType.VERSION).size());
        Evidence version = dependency.getEvidence(EvidenceType.VERSION).iterator().next();
        assertEquals("version", version.getName());
        assertEquals("1.3.0", version.getValue());

        assertTrue(dependency.getVulnerabilities().size() >= 3);
        assertTrue(dependency.getVulnerabilities().contains(new Vulnerability("CVE-2014-0013")));
        assertTrue(dependency.getVulnerabilities().contains(new Vulnerability("CVE-2014-0014")));
        assertTrue(dependency.getVulnerabilities().contains(new Vulnerability("CVE-2014-0046")));
    }
}
