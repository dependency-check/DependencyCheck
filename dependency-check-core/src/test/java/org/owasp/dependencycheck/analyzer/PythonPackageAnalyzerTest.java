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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;

import java.io.File;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for PythonPackageAnalyzer.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class PythonPackageAnalyzerTest extends BaseTest {

    /**
     * The package analyzer to test.
     */
    PythonPackageAnalyzer analyzer;

    /**
     * Setup the PtyhonPackageAnalyzer.
     *
     * @throws Exception if there is a problem
     */
    @Before
    public void setUp() throws Exception {
        analyzer = new PythonPackageAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize();
    }

    /**
     * Cleanup any resources used.
     *
     * @throws Exception if there is a problem
     */
    @After
    public void tearDown() throws Exception {
        analyzer.close();
        analyzer = null;
    }

    /**
     * Test of getName method, of class PythonPackageAnalyzer.
     */
    @Test
    public void testGetName() {
        assertEquals("Analyzer name wrong.", "Python Package Analyzer",
                analyzer.getName());
    }

    /**
     * Test of supportsExtension method, of class PythonPackageAnalyzer.
     */
    @Test
    public void testSupportsFileExtension() {
        assertTrue("Should support \"py\" extension.",
                analyzer.accept(new File("test.py")));
    }

    @Test
    public void testAnalyzeSourceMetadata() throws AnalysisException {
        eggtestAssertions(this,
                "python/eggtest/__init__.py");
    }

    public void eggtestAssertions(Object context, final String resource) throws AnalysisException {
        boolean found = false;
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                context, resource));
        analyzer.analyze(result, null);
        assertTrue("Expected vendor evidence to contain \"example\".", result
                .getVendorEvidence().toString().contains("example"));
        for (final Evidence e : result.getVersionEvidence()) {
            if ("0.0.1".equals(e.getValue())) {
                found = true;
                break;
            }
        }
        assertTrue("Version 0.0.1 not found in EggTest dependency.", found);
    }
}
