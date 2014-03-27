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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Tests for the AssemblyAnalyzer.
 *
 * @author colezlaw
 *
 */
public class AssemblyAnalyzerTest {

    private static final Logger LOGGER = Logger.getLogger(AssemblyAnalyzerTest.class.getName());

    AssemblyAnalyzer analyzer;

    /**
     * Sets up the analyzer.
     *
     * @throws Exception if anything goes sideways
     */
    @Before
    public void setUp() {
        try {
            analyzer = new AssemblyAnalyzer();
            analyzer.supportsExtension("dll");
            analyzer.initialize();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Exception setting up AssemblyAnalyzer. Tests will be incomplete", e);
            Assume.assumeNoException("Is mono installed? TESTS WILL BE INCOMPLETE", e);
        }
    }

    /**
     * Tests to make sure the name is correct.
     */
    @Test
    public void testGetName() {
        assertEquals("Assembly Analyzer", analyzer.getName());
    }

    @Test
    public void testAnalysis() throws Exception {
        File f = new File(AssemblyAnalyzerTest.class.getClassLoader().getResource("GrokAssembly.exe").getPath());
        Dependency d = new Dependency(f);
        analyzer.analyze(d, null);
        boolean foundVendor = false;
        for (Evidence e : d.getVendorEvidence().getEvidence("grokassembly", "vendor")) {
            if ("OWASP".equals(e.getValue())) {
                foundVendor = true;
            }
        }
        assertTrue(foundVendor);
        
        boolean foundProduct = false;
        for (Evidence e : d.getProductEvidence().getEvidence("grokassembly", "product")) {
            if ("GrokAssembly".equals(e.getValue())) {
                foundProduct = true;
            }
        }
        assertTrue(foundProduct);
    }

    @Test
    public void testLog4Net() throws Exception {
        File f = new File(AssemblyAnalyzerTest.class.getClassLoader().getResource("log4net.dll").getPath());
        Dependency d = new Dependency(f);
        analyzer.analyze(d, null);
        assertTrue(d.getVersionEvidence().getEvidence().contains(new Evidence("grokassembly", "version", "1.2.13.0", Confidence.HIGHEST)));
        assertTrue(d.getVendorEvidence().getEvidence().contains(new Evidence("grokassembly", "vendor", "The Apache Software Foundation", Confidence.HIGH)));
        assertTrue(d.getProductEvidence().getEvidence().contains(new Evidence("grokassembly", "product", "log4net", Confidence.HIGH)));
    }

    @Test
    public void testNonexistent() {
        Level oldLevel = Logger.getLogger(AssemblyAnalyzer.class.getName()).getLevel();
        Level oldDependency = Logger.getLogger(Dependency.class.getName()).getLevel();
        // Tweak the log level so the warning doesn't show in the console
        Logger.getLogger(AssemblyAnalyzer.class.getName()).setLevel(Level.OFF);
        Logger.getLogger(Dependency.class.getName()).setLevel(Level.OFF);
        File f = new File(AssemblyAnalyzerTest.class.getClassLoader().getResource("log4net.dll").getPath());
        File test = new File(f.getParent(), "nonexistent.dll");
        Dependency d = new Dependency(test);

        try {
            analyzer.analyze(d, null);
            fail("Expected an AnalysisException");
        } catch (AnalysisException ae) {
            assertEquals("File does not exist", ae.getMessage());
        } finally {
            Logger.getLogger(AssemblyAnalyzer.class.getName()).setLevel(oldLevel);
            Logger.getLogger(Dependency.class.getName()).setLevel(oldDependency);
        }
    }

    @Test
    public void testWithSettingMono() throws Exception {

        //This test doesn't work on Windows.
        assumeFalse(System.getProperty("os.name").startsWith("Windows"));

        String oldValue = Settings.getString(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH);
        // if oldValue is null, that means that neither the system property nor the setting has
        // been set. If that's the case, then we have to make it such that when we recover,
        // null still comes back. But you can't put a null value in a HashMap, so we have to set
        // the system property rather than the setting.
        if (oldValue == null) {
            System.setProperty(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH, "/yooser/bine/mono");
        } else {
            Settings.setString(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH, "/yooser/bine/mono");
        }

        Level oldLevel = Logger.getLogger(AssemblyAnalyzer.class.getName()).getLevel();
        try {
            // Tweak the logging to swallow the warning when testing
            Logger.getLogger(AssemblyAnalyzer.class.getName()).setLevel(Level.OFF);
            // Have to make a NEW analyzer because during setUp, it would have gotten the correct one
            AssemblyAnalyzer aanalyzer = new AssemblyAnalyzer();
            aanalyzer.supportsExtension("dll");
            aanalyzer.initialize();
            fail("Expected an AnalysisException");
        } catch (AnalysisException ae) {
            assertEquals("An error occured with the .NET AssemblyAnalyzer", ae.getMessage());
        } finally {
            // Recover the logger
            Logger.getLogger(AssemblyAnalyzer.class.getName()).setLevel(oldLevel);
            // Now recover the way we came in. If we had to set a System property, delete it. Otherwise,
            // reset the old value
            if (oldValue == null) {
                System.getProperties().remove(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH);
            } else {
                Settings.setString(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH, oldValue);
            }
        }
    }

    @After
    public void tearDown() throws Exception {
        analyzer.close();
    }
}
