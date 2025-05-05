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
 * Copyright (c) 2020 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for PipAnalyzerTest.
 */
class PipAnalyzerTest extends BaseDBTestCase {

    /**
     * The analyzer to test.
     */
    private PipAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new PipAnalyzer();
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
        super.tearDown();
    }

    /**
     * Test of getName method, of class PipAnalyzer.
     */
    @Test
    void testGetName() {
        assertEquals("pip Analyzer", analyzer.getName());
    }

    /**
     * Test of supportsExtension method, of class PipAnalyzer.
     */
    @Test
    void testSupportsFiles() {
        assertTrue(analyzer.accept(new File("requirements.txt")));
        assertFalse(analyzer.accept(new File("requirements2.txt")));
        assertFalse(analyzer.accept(new File("requirements.py")));
        assertFalse(analyzer.accept(new File("requirements")));
    }

    /**
     * Test of inspect method, of class PipAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testAnalyzePackageJson() throws Exception {
        try (Engine engine = new Engine(getSettings())) {
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "requirements.txt"));
            engine.addDependency(result);
            analyzer.analyze(result, engine);
            assertFalse(ArrayUtils.contains(engine.getDependencies(), result));
            assertEquals(24, engine.getDependencies().length);
            boolean foundPyYAML = false;
            boolean foundCryptography = false;
            for (Dependency d : engine.getDependencies()) {
                if ("PyYAML".equals(d.getName())) {
                    foundPyYAML = true;
                    assertEquals("3.12", d.getVersion());
                    assertThat(d.getDisplayFileName(), equalTo("PyYAML:3.12"));
                    assertEquals(PythonDistributionAnalyzer.DEPENDENCY_ECOSYSTEM, d.getEcosystem());
                }
                if ("cryptography".equals(d.getName())) {
                    foundCryptography = true;
                    assertEquals("1.8.2", d.getVersion());
                    assertThat(d.getDisplayFileName(), equalTo("cryptography:1.8.2"));
                    assertEquals(PythonDistributionAnalyzer.DEPENDENCY_ECOSYSTEM, d.getEcosystem());
                }
            }
            assertTrue(foundPyYAML, "Expected to find PyYAML");
            assertTrue(foundCryptography, "Expected to find cryptography");
        }
    }
}
