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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.analyzer.exception.UnexpectedAnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Tests for the AssemblyAnalyzer.
 *
 * @author colezlaw
 *
 */
class AssemblyAnalyzerTest extends BaseTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(AssemblyAnalyzerTest.class);

    private static final String LOG_KEY = "org.slf4j.simpleLogger.org.owasp.dependencycheck.analyzer.AssemblyAnalyzer";

    private AssemblyAnalyzer analyzer;

    /**
     * Sets up the analyzer.
     *
     * @throws Exception if anything goes sideways
     */
    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        try {
            analyzer = new AssemblyAnalyzer();
            analyzer.initialize(getSettings());
            analyzer.accept(new File("test.dll")); // trick into "thinking it is active"
            analyzer.prepare(null);
            assertGrokAssembly();
        } catch (Exception e) {
            if (e.getMessage().contains("Could not execute .NET AssemblyAnalyzer")) {
                LOGGER.warn("Exception setting up AssemblyAnalyzer. Tests will be incomplete");
            } else {
                LOGGER.warn("Exception setting up AssemblyAnalyzer. Tests will be incomplete");
            }
            assumeTrue(false, "Is dotnet installed? TESTS WILL BE INCOMPLETE: " + e);
        }
    }

    private void assertGrokAssembly() {
        // There must be an .exe and a .config files created in the temp
        // directory and they must match the resources they were created from.
        File grokAssemblyExeFile = analyzer.getGrokAssemblyPath();
        assertTrue(grokAssemblyExeFile.isFile(), "The GrokAssembly executable was not created.");
    }

    /**
     * Tests to make sure the name is correct.
     */
    @Test
    void testGetName() {
        assertEquals("Assembly Analyzer", analyzer.getName());
    }

    @Test
    void testAnalysis() throws Exception {
        assumeTrue(analyzer.buildArgumentList() != null);
        File f = analyzer.getGrokAssemblyPath();
        Dependency d = new Dependency(f);
        analyzer.analyze(d, null);
        assertTrue(d.contains(EvidenceType.VENDOR, new Evidence("grokassembly", "CompanyName", "OWASP Contributors", Confidence.HIGHEST)));
        assertTrue(d.contains(EvidenceType.PRODUCT, new Evidence("grokassembly", "ProductName", "GrokAssembly", Confidence.HIGHEST)));
    }

    @Test
    void testLog4Net() throws Exception {
        assumeTrue(analyzer.buildArgumentList() != null);
        File f = BaseTest.getResourceAsFile(this, "log4net.dll");

        Dependency d = new Dependency(f);
        analyzer.analyze(d, null);
        assertTrue(d.contains(EvidenceType.VERSION, new Evidence("grokassembly", "FileVersion", "1.2.13.0", Confidence.HIGH)));
        assertEquals("1.2.13.0", d.getVersion());
        assertTrue(d.contains(EvidenceType.VENDOR, new Evidence("grokassembly", "CompanyName", "The Apache Software Foundation", Confidence.HIGHEST)));
        assertTrue(d.contains(EvidenceType.PRODUCT, new Evidence("grokassembly", "ProductName", "log4net", Confidence.HIGHEST)));
        assertEquals("log4net", d.getName());
    }

    @Test
    void testNonexistent() {
        assumeTrue(analyzer.buildArgumentList() != null);

        // Tweak the log level so the warning doesn't show in the console
        String oldProp = System.getProperty(LOG_KEY, "info");
        File f = BaseTest.getResourceAsFile(this, "log4net.dll");
        File test = new File(f.getParent(), "nonexistent.dll");
        Dependency d = new Dependency(test);

        try {
            AnalysisException ae = assertThrows(AnalysisException.class, () -> analyzer.analyze(d, null),
                "Expected an AnalysisException");
            assertTrue(ae.getMessage().contains("nonexistent.dll does not exist and cannot be analyzed by dependency-check"));
        } finally {
            System.setProperty(LOG_KEY, oldProp);
        }
    }

    @Test
    void testWithSettingMono() {

        //This test doesn't work on Windows.
        assumeFalse(System.getProperty("os.name").startsWith("Windows"));

        String oldValue = getSettings().getString(Settings.KEYS.ANALYZER_ASSEMBLY_DOTNET_PATH);
        // if oldValue is null, that means that neither the system property nor the setting has
        // been set. If that's the case, then we have to make it such that when we recover,
        // null still comes back. But you can't put a null value in a HashMap, so we have to set
        // the system property rather than the setting.
        System.setProperty(Settings.KEYS.ANALYZER_ASSEMBLY_DOTNET_PATH, "/yooser/bine/mono");

        String oldProp = System.getProperty(LOG_KEY, "info");
        try {
            // Tweak the logging to swallow the warning when testing
            System.setProperty(LOG_KEY, "error");
            // Have to make a NEW analyzer because during setUp, it would have gotten the correct one
            AssemblyAnalyzer aanalyzer = new AssemblyAnalyzer();
            aanalyzer.initialize(getSettings());
            aanalyzer.accept(new File("test.dll")); // trick into "thinking it is active"

            InitializationException ae = assertThrows(InitializationException.class, () -> aanalyzer.prepare(null),
                    "Expected an InitializationException");
            assertEquals("An error occurred with the .NET AssemblyAnalyzer, is the dotnet 8.0 runtime or sdk installed?", ae.getMessage());
        } finally {
            System.setProperty(LOG_KEY, oldProp);
            // Recover the logger
            // Now recover the way we came in. If we had to set a System property, delete it. Otherwise,
            // reset the old value
            if (oldValue == null) {
                System.getProperties().remove(Settings.KEYS.ANALYZER_ASSEMBLY_DOTNET_PATH);
            } else {
                System.setProperty(Settings.KEYS.ANALYZER_ASSEMBLY_DOTNET_PATH, oldValue);
            }
        }
    }

    @AfterEach
    @Override
    public void tearDown() throws Exception {
        try {
            analyzer.closeAnalyzer();
        } catch (Exception ex) {
            throw new UnexpectedAnalysisException(ex);
        } finally {
            super.tearDown();
        }
    }
}
