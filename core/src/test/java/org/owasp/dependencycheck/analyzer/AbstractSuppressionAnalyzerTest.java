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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.Engine.Mode;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.Settings.KEYS;
import org.owasp.dependencycheck.xml.suppression.SuppressionRule;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.owasp.dependencycheck.analyzer.AbstractSuppressionAnalyzer.SUPPRESSION_OBJECT_KEY;

/**
 * @author Jeremy Long
 */
class AbstractSuppressionAnalyzerTest extends BaseTest {

    /**
     * A second suppression file to test with.
     */
    private static final String OTHER_SUPPRESSIONS_FILE = "other-suppressions.xml";

    /**
     * Suppression file to test with.
     */
    private static final String SUPPRESSIONS_FILE = "suppressions.xml";

    private AbstractSuppressionAnalyzer instance;

    @BeforeEach
    void createObjectUnderTest() {
        instance = new AbstractSuppressionAnalyzerImpl();
    }

    /**
     * Test of getSupportedExtensions method, of class
     * AbstractSuppressionAnalyzer.
     */
    @Test
    void testGetSupportedExtensions() {
        Set<String> result = instance.getSupportedExtensions();
        assertNull(result);
    }

    /**
     * Test of getRules method, of class AbstractSuppressionAnalyzer for
     * suppression file declared as URL.
     */
    @Test
    void testGetRulesFromSuppressionFileFromURL() throws Exception {
        final String fileUrl = getClass().getClassLoader().getResource(SUPPRESSIONS_FILE).toURI().toURL().toString();
        final int numberOfExtraLoadedRules = getNumberOfRulesLoadedFromPath(fileUrl) - getNumberOfRulesLoadedInCoreFile();
        assertEquals(5, numberOfExtraLoadedRules, "Expected 5 extra rules in the given path");
    }

    /**
     * Test of getRules method, of class AbstractSuppressionAnalyzer for
     * suppression file on the class path.
     */
    @Test
    void testGetRulesFromSuppressionFileInClasspath() throws Exception {
        final int numberOfExtraLoadedRules = getNumberOfRulesLoadedFromPath(SUPPRESSIONS_FILE) - getNumberOfRulesLoadedInCoreFile();
        assertEquals(5, numberOfExtraLoadedRules, "Expected 5 extra rules in the given file");
    }

    /**
     * Assert that rules are loaded from multiple files if multiple files are
     * defined in the {@link Settings}.
     */
    @Test
    void testGetRulesFromMultipleSuppressionFiles() throws Exception {
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

    @Test
    void testFailureToLocateSuppressionFileAnywhere() {
        getSettings().setString(Settings.KEYS.SUPPRESSION_FILE, "doesnotexist.xml");
        instance.initialize(getSettings());
        Engine engine = new Engine(Mode.EVIDENCE_COLLECTION, getSettings());
        assertThrows(InitializationException.class, () ->
            instance.prepare(engine));
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
        Engine engine = prepareSuppressions();
        return AbstractSuppressionAnalyzer.getRuleCount(engine);
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
        Engine engine = prepareSuppressions();
        return AbstractSuppressionAnalyzer.getRuleCount(engine);
    }

    private @NonNull Engine prepareSuppressions() throws InvalidSettingException, InitializationException {
        final AbstractSuppressionAnalyzerImpl fileAnalyzer = new AbstractSuppressionAnalyzerImpl();
        fileAnalyzer.initialize(getSettings());
        Downloader.getInstance().configure(getSettings());
        Engine engine = new Engine(Mode.EVIDENCE_COLLECTION, getSettings());
        fileAnalyzer.prepare(engine);
        return engine;
    }

    @Nested
    class CoreSuppressionsLoading {
        @Test
        void testLoadCorePackagedSuppressions() throws Exception {
            List<SuppressionRule> baseRules = assertAllBaseSuppressionRulesAreMarkedCorrectly();

            assertAllHostedSnapshotSuppressionsAreMarkedAsBase(baseRules);
        }

        private void assertAllHostedSnapshotSuppressionsAreMarkedAsBase(List<SuppressionRule> baseRules) throws InvalidSettingException, InitializationException {
            getSettings().setBoolean(KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setString(KEYS.HOSTED_SUPPRESSIONS_URL, "https://intentionally-bad-url/hosted-suppressions.xml");
            Engine engine = prepareSuppressions();

            @SuppressWarnings("unchecked") List<SuppressionRule> allRules = (List<SuppressionRule>) engine.getObject(SUPPRESSION_OBJECT_KEY);

            List<SuppressionRule> hostedSnapshotRules = allRules.stream().filter(r -> !baseRules.contains(r)).collect(Collectors.toList());
            assertThat(hostedSnapshotRules, not(empty()));
            assertThat("Expected all suppressions in hosted suppressions snapshot file to be marked as base", allRulesNotMarkedAsBase(hostedSnapshotRules), empty());
        }

        private @NonNull List<SuppressionRule> assertAllBaseSuppressionRulesAreMarkedCorrectly() throws InvalidSettingException, InitializationException {
            getSettings().setBoolean(KEYS.HOSTED_SUPPRESSIONS_ENABLED, false);
            Engine engine = prepareSuppressions();

            @SuppressWarnings("unchecked") List<SuppressionRule> baseRules = (List<SuppressionRule>) engine.getObject(SUPPRESSION_OBJECT_KEY);
            assertThat(baseRules, not(empty()));
            assertThat("Expected all suppressions in base file to be marked as base", allRulesNotMarkedAsBase(baseRules), empty());
            return baseRules;
        }

        private @NonNull List<SuppressionRule> allRulesNotMarkedAsBase(List<SuppressionRule> baseRules) {
            return baseRules.stream().filter(r -> !r.isBase()).collect(Collectors.toList());
        }
    }

    public static class AbstractSuppressionAnalyzerImpl extends AbstractSuppressionAnalyzer {

        @Override
        public void analyzeDependency(Dependency dependency, Engine engine) {
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
