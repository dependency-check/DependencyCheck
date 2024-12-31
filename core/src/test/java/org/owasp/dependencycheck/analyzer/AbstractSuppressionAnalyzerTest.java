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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.Engine.Mode;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.Settings.KEYS;
import org.owasp.dependencycheck.xml.suppression.SuppressionRule;

/**
 * @author Jeremy Long
 */
public class AbstractSuppressionAnalyzerTest extends BaseTest {

    /**
     * A second suppression file to test with.
     */
    private static final String OTHER_SUPPRESSIONS_FILE = "other-suppressions.xml";

    /**
     * Suppression file to test with.
     */
    private static final String SUPPRESSIONS_FILE = "suppressions.xml";

    private AbstractSuppressionAnalyzer instance;

    @Before
    public void createObjectUnderTest() throws Exception {
        instance = new AbstractSuppressionAnalyzerImpl();
    }

    /**
     * Test of getSupportedExtensions method, of class
     * AbstractSuppressionAnalyzer.
     */
    @Test
    public void testGetSupportedExtensions() {
        Set<String> result = instance.getSupportedExtensions();
        assertNull(result);
    }

    /**
     * Test of getRules method, of class AbstractSuppressionAnalyzer for
     * suppression file declared as URL.
     */
    @Test
    public void testGetRulesFromSuppressionFileFromURL() throws Exception {
        final String fileUrl = getClass().getClassLoader().getResource(SUPPRESSIONS_FILE).toURI().toURL().toString();
        final int numberOfExtraLoadedRules = getNumberOfRulesLoadedFromPath(fileUrl) - getNumberOfRulesLoadedInCoreFile();
        assertEquals("Expected 5 extra rules in the given path", 5, numberOfExtraLoadedRules);
    }

    /**
     * Test of getRules method, of class AbstractSuppressionAnalyzer for
     * suppression file on the class path.
     */
    @Test
    public void testGetRulesFromSuppressionFileInClasspath() throws Exception {
        final int numberOfExtraLoadedRules = getNumberOfRulesLoadedFromPath(SUPPRESSIONS_FILE) - getNumberOfRulesLoadedInCoreFile();
        assertEquals("Expected 5 extra rules in the given file", 5, numberOfExtraLoadedRules);
    }

    /**
     * Assert that rules are loaded from multiple files if multiple files are
     * defined in the {@link Settings}.
     */
    @Test
    public void testGetRulesFromMultipleSuppressionFiles() throws Exception {
        final int rulesInCoreFile = getNumberOfRulesLoadedInCoreFile();

        // GIVEN suppression rules from one file
        final int rulesInFirstFile = getNumberOfRulesLoadedFromPath(SUPPRESSIONS_FILE) - rulesInCoreFile;

        // AND suppression rules from another file
        final int rulesInSecondFile = getNumberOfRulesLoadedFromPath(OTHER_SUPPRESSIONS_FILE) - rulesInCoreFile;

        // WHEN initializing with both suppression files
        final String[] suppressionFiles = {SUPPRESSIONS_FILE, OTHER_SUPPRESSIONS_FILE};
        getSettings().setArrayIfNotEmpty(KEYS.SUPPRESSION_FILE, suppressionFiles);
        instance.initialize(getSettings());
        Engine engine = new Engine(getSettings());
        instance.prepare(engine);

        // THEN rules from both files were loaded
        final int expectedSize = rulesInFirstFile + rulesInSecondFile + rulesInCoreFile;
        assertThat("Expected suppressions from both files", instance.getRuleCount(engine), is(expectedSize));
    }

    @Test(expected = InitializationException.class)
    public void testFailureToLocateSuppressionFileAnywhere() throws Exception {
        getSettings().setString(Settings.KEYS.SUPPRESSION_FILE, "doesnotexist.xml");
        instance.initialize(getSettings());
        Engine engine = new Engine(Mode.EVIDENCE_COLLECTION, getSettings());
        instance.prepare(engine);
    }

    /**
     * Return the number of rules that are loaded from the core suppression
     * file.
     *
     * @return the number of rules defined in the core suppression file.
     * @throws Exception if loading the rules fails.
     */
    private int getNumberOfRulesLoadedInCoreFile() throws Exception {
        getSettings().removeProperty(KEYS.SUPPRESSION_FILE);
        final AbstractSuppressionAnalyzerImpl coreFileAnalyzer = new AbstractSuppressionAnalyzerImpl();
        coreFileAnalyzer.initialize(getSettings());
        Engine engine = new Engine(Mode.EVIDENCE_COLLECTION, getSettings());
        coreFileAnalyzer.prepare(engine);
        int count = AbstractSuppressionAnalyzer.getRuleCount(engine);
        return count;
    }

    /**
     * Load a file into the {@link AbstractSuppressionAnalyzer} and return the
     * number of rules loaded.
     *
     * @param path the path to load.
     * @return the number of rules that were loaded (including the core rules).
     * @throws Exception if loading the rules fails.
     */
    private int getNumberOfRulesLoadedFromPath(final String path) throws Exception {
        getSettings().setString(KEYS.SUPPRESSION_FILE, path);
        final AbstractSuppressionAnalyzerImpl fileAnalyzer = new AbstractSuppressionAnalyzerImpl();
        fileAnalyzer.initialize(getSettings());
        Downloader.getInstance().configure(getSettings());
        Engine engine = new Engine(Mode.EVIDENCE_COLLECTION, getSettings());
        fileAnalyzer.prepare(engine);
        int count = AbstractSuppressionAnalyzer.getRuleCount(engine);
        return count;
    }

    public static class AbstractSuppressionAnalyzerImpl extends AbstractSuppressionAnalyzer {

        @Override
        public void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        public String getName() {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        public AnalysisPhase getAnalysisPhase() {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        protected String getAnalyzerEnabledSettingKey() {
            return "unknown";
        }

        @Override
        public boolean filter(SuppressionRule rule) {
            return false;
        }
    }

}
