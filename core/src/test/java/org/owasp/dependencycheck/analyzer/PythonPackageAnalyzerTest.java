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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for PythonPackageAnalyzer.
 *
 * @author Dale Visser
 */
class PythonPackageAnalyzerTest extends BaseTest {

    /**
     * The package analyzer to test.
     */
    private PythonPackageAnalyzer analyzer;

    /**
     * Setup the {@link PythonPackageAnalyzer}.
     *
     * @throws Exception if there is a problem
     */
    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new PythonPackageAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize(getSettings());
        analyzer.prepare(null);
    }

    /**
     * Cleanup any resources used.
     *
     * @throws Exception if there is a problem
     */
    @AfterEach
    @Override
    public void tearDown() throws Exception {
        analyzer.close();
        super.tearDown();
    }

    /**
     * Test of getName method, of class PythonPackageAnalyzer.
     */
    @Test
    void testGetName() {
        assertEquals("Python Package Analyzer",
                analyzer.getName(),
                "Analyzer name wrong.");
    }

    /**
     * Test of supportsExtension method, of class PythonPackageAnalyzer.
     */
    @Test
    void testSupportsFileExtension() {
        assertTrue(analyzer.accept(new File("test.py")),
                "Should support \"py\" extension.");
    }

    @Test
    void testAnalyzeSourceMetadata() throws AnalysisException {
        boolean found = false;
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "python/eggtest/__init__.py"));
        analyzer.analyze(result, null);
        assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("example"),
                "Expected vendor evidence to contain \"example\".");
        for (final Evidence e : result.getEvidence(EvidenceType.VERSION)) {
            if ("0.0.1".equals(e.getValue())) {
                found = true;
                break;
            }
        }
        assertTrue(found, "Version 0.0.1 not found in EggTest dependency.");
        assertEquals("0.0.1",result.getVersion());
        assertEquals("eggtest",result.getName());
        assertEquals("eggtest:0.0.1",result.getDisplayFileName());
        assertEquals(PythonPackageAnalyzer.DEPENDENCY_ECOSYSTEM,result.getEcosystem());
    }
}
