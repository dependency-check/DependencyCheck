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
 * Copyright (c) 2015 Institute for Defense Analyses. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for PythonDistributionAnalyzer.
 *
 * @author Dale Visser
 */
class PythonDistributionAnalyzerTest extends BaseTest {

    /**
     * The analyzer to test.
     */
    private PythonDistributionAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new PythonDistributionAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize(getSettings());
        analyzer.prepare(null);
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @AfterEach
    @Override
    public void tearDown() throws Exception {
        analyzer.close();
        super.tearDown();
    }

    /**
     * Test of getName method, of class PythonDistributionAnalyzer.
     */
    @Test
    void testGetName() {
        assertEquals("Python Distribution Analyzer",
                analyzer.getName(),
                "Analyzer name wrong.");
    }

    /**
     * Test of supportsExtension method, of class PythonDistributionAnalyzer.
     */
    @Test
    void testSupportsFiles() {
        assertTrue(analyzer.accept(new File("test.whl")),
                "Should support \"whl\" extension.");
        assertTrue(analyzer.accept(new File("test.egg")),
                "Should support \"egg\" extension.");
        assertTrue(analyzer.accept(new File("test.zip")),
                "Should support \"zip\" extension.");
        assertTrue(analyzer.accept(new File("METADATA")),
                "Should support \"METADATA\" extension.");
        assertTrue(analyzer.accept(new File("PKG-INFO")),
                "Should support \"PKG-INFO\" extension.");
    }

    /**
     * Test of inspect method, of class PythonDistributionAnalyzer.
     */
    @Test
    void testAnalyzeWheel() {
        assertDoesNotThrow(() -> djangoAssertions(new Dependency(BaseTest.getResourceAsFile(this,
                "python/Django-1.7.2-py2.py3-none-any.whl"))));
    }

    /**
     * Test of inspect method, of class PythonDistributionAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testAnalyzeSitePackage() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "python/site-packages/Django-1.7.2.dist-info/METADATA"));
        djangoAssertions(result);
        }

    private void djangoAssertions(final Dependency result)
            throws AnalysisException {
        boolean found = false;
        analyzer.analyze(result, null);
        assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("djangoproject"),
                "Expected vendor evidence to contain \"djangoproject\".");
        for (final Evidence e : result.getEvidence(EvidenceType.VERSION)) {
            if ("Version".equals(e.getName()) && "1.7.2".equals(e.getValue())) {
                found = true;
                break;
            }
        }
        assertTrue(found, "Version 1.7.2 not found in Django dependency.");
        assertEquals("1.7.2",result.getVersion());
        assertEquals("Django",result.getName());
        assertEquals("Django:1.7.2",result.getDisplayFileName());
        assertEquals(PythonDistributionAnalyzer.DEPENDENCY_ECOSYSTEM,result.getEcosystem());
    }

    @Test
    void testAnalyzeEggInfoFolder() {
        assertDoesNotThrow(() -> eggtestAssertions(this, "python/site-packages/EggTest.egg-info/PKG-INFO"));
    }

    @Test
    void testAnalyzeEggArchive() {
        assertDoesNotThrow(() -> eggtestAssertions(this, "python/dist/EggTest-0.0.1-py2.7.egg"));
    }

    @Test
    void testAnalyzeEggArchiveNamedZip() {
        assertDoesNotThrow(() -> eggtestAssertions(this, "python/dist/EggTest-0.0.1-py2.7.zip"));
    }

    @Test
    void testAnalyzeEggFolder() {
        assertDoesNotThrow(() -> eggtestAssertions(this, "python/site-packages/EggTest-0.0.1-py2.7.egg/EGG-INFO/PKG-INFO"));
    }

    private void eggtestAssertions(Object context, final String resource) throws AnalysisException {
        boolean found = false;
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                context, resource));
        analyzer.analyze(result, null);
        assertTrue(result
                .getEvidence(EvidenceType.VENDOR).toString().contains("example"), "Expected vendor evidence to contain \"example\".");
        for (final Evidence e : result.getEvidence(EvidenceType.VERSION)) {
            if ("0.0.1".equals(e.getValue())) {
                found = true;
                break;
            }
        }
        assertTrue(found, "Version 0.0.1 not found in EggTest dependency.");
        assertEquals("0.0.1",result.getVersion());
        assertEquals("EggTest",result.getName());
        assertEquals("EggTest:0.0.1",result.getDisplayFileName());
        assertEquals(PythonDistributionAnalyzer.DEPENDENCY_ECOSYSTEM,result.getEcosystem());
    }
}
