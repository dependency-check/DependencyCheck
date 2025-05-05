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
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for AutoconfAnalyzer. The test resources under autoconf/ were
 * obtained from outside open source software projects. Links to those projects
 * are given below.
 *
 * @author Dale Visser
 * @see <a href="http://readable.sourceforge.net/">Readable Lisp S-expressions
 * Project</a>
 * @see <a href="https://gnu.org/software/binutils/">GNU Binutils</a>
 * @see <a href="https://gnu.org/software/ghostscript/">GNU Ghostscript</a>
 */
class AutoconfAnalyzerTest extends BaseTest {

    /**
     * The analyzer to test.
     */
    private AutoconfAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new AutoconfAnalyzer();
        analyzer.initialize(getSettings());
        analyzer.setFilesMatched(true);
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
        analyzer = null;
        super.tearDown();
    }

    /**
     * Test whether expected evidence is gathered from Ghostscript's configure.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testAnalyzeConfigureAC1() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "autoconf/ghostscript/configure.ac"));
        analyzer.analyze(result, null);
        //TODO fix these
        assertTrue(result.contains(EvidenceType.VENDOR, new Evidence("configure.ac", "Bug report address", "gnu-ghostscript-bug@gnu.org", Confidence.HIGH)));
        assertTrue(result.contains(EvidenceType.PRODUCT, new Evidence("configure.ac", "Package", "gnu-ghostscript", Confidence.HIGHEST)));
        assertTrue(result.contains(EvidenceType.VERSION, new Evidence("configure.ac", "Package Version", "8.62.0", Confidence.HIGHEST)));
    }

    /**
     * Test whether expected evidence is gathered from Readable's configure.ac.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testAnalyzeConfigureAC2() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "autoconf/readable-code/configure.ac"));
        analyzer.analyze(result, null);

        assertTrue(result.contains(EvidenceType.VENDOR, new Evidence("configure.ac", "Bug report address", "dwheeler@dwheeler.com", Confidence.HIGH)));
        assertTrue(result.contains(EvidenceType.PRODUCT, new Evidence("configure.ac", "Package", "readable", Confidence.HIGHEST)));
        assertTrue(result.contains(EvidenceType.VERSION, new Evidence("configure.ac", "Package Version", "1.0.7", Confidence.HIGHEST)));
        assertTrue(result.contains(EvidenceType.VENDOR, new Evidence("configure.ac", "URL", "http://readable.sourceforge.net/", Confidence.HIGH)));
    }

    /**
     * Test whether expected evidence is gathered from GNU Binutil's configure.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testAnalyzeConfigureScript() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "autoconf/binutils/configure"));
        analyzer.analyze(result, null);

        assertTrue(result.contains(EvidenceType.PRODUCT, new Evidence("configure", "NAME", "binutils", Confidence.HIGHEST)));
        assertTrue(result.contains(EvidenceType.VERSION, new Evidence("configure", "VERSION", "2.25.51", Confidence.HIGHEST)));
    }

    /**
     * Test whether expected evidence is gathered from GNU Ghostscript's
     * configure.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testAnalyzeReadableConfigureScript() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "autoconf/readable-code/configure"));
        analyzer.analyze(result, null);

        assertTrue(result.contains(EvidenceType.VENDOR, new Evidence("configure", "BUGREPORT", "dwheeler@dwheeler.com", Confidence.HIGH)));
        assertTrue(result.contains(EvidenceType.PRODUCT, new Evidence("configure", "NAME", "readable", Confidence.HIGHEST)));
        assertTrue(result.contains(EvidenceType.VERSION, new Evidence("configure", "VERSION", "1.0.7", Confidence.HIGHEST)));
        assertTrue(result.contains(EvidenceType.VENDOR, new Evidence("configure", "URL", "http://readable.sourceforge.net/", Confidence.HIGH)));
    }

    /**
     * Test of getName method, of {@link AutoconfAnalyzer}.
     */
    @Test
    void testGetName() {
        assertEquals("Autoconf Analyzer",
                analyzer.getName(),
                "Analyzer name wrong.");
    }

    /**
     * Test of {@link AutoconfAnalyzer#accept(File)}.
     */
    @Test
    void testSupportsFileExtension() {
        assertTrue(analyzer.accept(new File("configure.ac")),
                "Should support \"ac\" extension.");
        assertTrue(analyzer.accept(new File("configure.in")),
                "Should support \"in\" extension.");
        assertTrue(analyzer.accept(new File("configure")),
                "Should support \"configure\" extension.");
    }
}
