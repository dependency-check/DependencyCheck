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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.Engine.Mode;
import org.owasp.dependencycheck.data.update.HostedSuppressionsDataSource;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.Settings.KEYS;
import org.owasp.dependencycheck.xml.suppression.SuppressionParseException;
import org.owasp.dependencycheck.xml.suppression.SuppressionRule;

import java.util.List;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.owasp.dependencycheck.analyzer.AbstractSuppressionAnalyzer.SUPPRESSION_OBJECT_KEY;

/**
 * @author Jeremy Long
 */
class AbstractSuppressionAnalyzerTest extends BaseTest {

    /**
     * A second suppression file to test with.
     */
    private static final String OTHER_TEST_SUPPRESSIONS_FILE = "other-suppressions.xml";

    /**
     * Suppression file to test with.
     */
    private static final String TEST_SUPPRESSIONS_FILE = "suppressions.xml";
    private static final int TEST_SUPPRESSIONS_EXPECTED_COUNT = 5;

    private Engine engine;

    @AfterEach
    void cleanUp() {
        if (engine != null) {
            new HostedSuppressionsDataSource().purge(engine);
            engine.close();
        }
    }

    private String testSuppressionsFileUrl() {
        return BaseTest.getResourceAsUrlString(this, TEST_SUPPRESSIONS_FILE);
    }

    @Nested
    class BasePackagedSuppressionsLoading {
        @Test
        void packagedBaseSuppressions() throws Exception {
            engine = prepareBaseSuppressionsOnly();
            @SuppressWarnings("unchecked") List<SuppressionRule> rules = (List<SuppressionRule>) engine.getObject(SUPPRESSION_OBJECT_KEY);
            assertThat(rules, not(empty()));
            assertThat("Expected all suppressions in base file to be marked as base", allRulesNotMarkedAsBase(rules), empty());
        }
    }

    @Nested
    class HostedSuppressionsLoading {
        @Test
        void packagedSnapshotHostedSuppressionsLoadedEvenIfRemoteHostedSuppressionsDisabled() throws Exception {
            getSettings().setBoolean(KEYS.HOSTED_SUPPRESSIONS_ENABLED, false);
            engine = prepareHostedSuppressionsOnly();
            @SuppressWarnings("unchecked") List<SuppressionRule> rules = (List<SuppressionRule>) engine.getObject(SUPPRESSION_OBJECT_KEY);
            assertThat(rules, not(empty()));
            assertThat("Expected all suppressions in hosted suppressions snapshot file to be marked as base", allRulesNotMarkedAsBase(rules), empty());
        }

        @Test
        void packagedSnapshotHostedSuppressionsLoadedIfAutoUpdateDisabled() throws Exception {
            getSettings().setBoolean(KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setBoolean(KEYS.AUTO_UPDATE, false);
            engine = prepareHostedSuppressionsOnly();
            assertThat(AbstractSuppressionAnalyzer.getRuleCount(engine), greaterThan(0));
        }
        @Test
        void packagedSnapshotHostedSuppressionsLoadedIfRemoteHostedSuppressionsFail() throws Exception {
            getSettings().setBoolean(KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setBoolean(KEYS.AUTO_UPDATE, true);
            getSettings().setString(KEYS.HOSTED_SUPPRESSIONS_URL, "file:///does-not-exist.xml");
            engine = prepareHostedSuppressionsOnly();
            assertThat(AbstractSuppressionAnalyzer.getRuleCount(engine), greaterThan(0));
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void ignoresHostedSuppressionsIfUrlDoesntIncludeAFileNameRegardlessOfEnabledState(boolean hostedSuppressionsEnabled) throws Exception {
            getSettings().setBoolean(KEYS.HOSTED_SUPPRESSIONS_ENABLED, hostedSuppressionsEnabled);
            getSettings().setString(KEYS.HOSTED_SUPPRESSIONS_URL, "https://valid.url.but.no.file/");
            engine = prepareHostedSuppressionsOnly();
            assertThat(AbstractSuppressionAnalyzer.getRuleCount(engine), is(0));
        }

        @Test
        void ignoresHostedSuppressionsIfCannotBeParsedFromRemote() throws Exception {
            getSettings().setBoolean(KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setString(KEYS.HOSTED_SUPPRESSIONS_URL, BaseTest.getResourceAsUrlString(this, "suppressions-invalid.xml"));
            engine = prepareHostedSuppressionsOnly();
            assertThat(AbstractSuppressionAnalyzer.getRuleCount(engine), is(0));
        }

        @Test
        void prefersRemoteHostedSuppressionsIfEnabled() throws Exception {
            getSettings().setBoolean(KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setBoolean(KEYS.AUTO_UPDATE, true);
            getSettings().setString(KEYS.HOSTED_SUPPRESSIONS_URL, testSuppressionsFileUrl());
            engine = prepareHostedSuppressionsOnly();
            assertThat(AbstractSuppressionAnalyzer.getRuleCount(engine), is(TEST_SUPPRESSIONS_EXPECTED_COUNT));
        }

        @Test
        void prefersRemoteHostedSuppressionsIfEnabledAndForced() throws Exception {
            getSettings().setBoolean(KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setBoolean(KEYS.AUTO_UPDATE, false);
            getSettings().setBoolean(KEYS.HOSTED_SUPPRESSIONS_FORCEUPDATE, true);
            getSettings().setString(KEYS.HOSTED_SUPPRESSIONS_URL, testSuppressionsFileUrl());
            engine = prepareHostedSuppressionsOnly();
            assertThat(AbstractSuppressionAnalyzer.getRuleCount(engine), is(TEST_SUPPRESSIONS_EXPECTED_COUNT));
        }
    }

    @Nested
    class UserSuppressionsLoading {
        /**
         * Test of getRules method, of class AbstractSuppressionAnalyzer for
         * suppression file declared as URL.
         */
        @Test
        void testGetRulesFromSuppressionFileFromURL() throws Exception {
            final int numberOfExtraLoadedRules = getNumberOfRulesLoadedFromPath(testSuppressionsFileUrl()) - getNumberOfRulesLoadedInCoreFile();
            assertEquals(TEST_SUPPRESSIONS_EXPECTED_COUNT, numberOfExtraLoadedRules, "Wrong # of expected extra user suppression rules");
        }

        /**
         * Test of getRules method, of class AbstractSuppressionAnalyzer for
         * suppression file on the class path.
         */
        @Test
        void testGetRulesFromSuppressionFileInClasspath() throws Exception {
            final int numberOfExtraLoadedRules = getNumberOfRulesLoadedFromPath(TEST_SUPPRESSIONS_FILE) - getNumberOfRulesLoadedInCoreFile();
            assertEquals(TEST_SUPPRESSIONS_EXPECTED_COUNT, numberOfExtraLoadedRules, "Wrong # of expected extra user suppression rules");
        }

        /**
         * Assert that rules are loaded from multiple files if multiple files are
         * defined in the {@link Settings}.
         */
        @Test
        void testGetRulesFromMultipleSuppressionFiles() throws Exception {
            final int rulesInCoreFile = getNumberOfRulesLoadedInCoreFile();

            // GIVEN suppression rules from one file
            final int rulesInFirstFile = getNumberOfRulesLoadedFromPath(TEST_SUPPRESSIONS_FILE) - rulesInCoreFile;

            // AND suppression rules from another file
            final int rulesInSecondFile = getNumberOfRulesLoadedFromPath(OTHER_TEST_SUPPRESSIONS_FILE) - rulesInCoreFile;

            // WHEN initializing with both suppression files
            final String[] suppressionFiles = {TEST_SUPPRESSIONS_FILE, OTHER_TEST_SUPPRESSIONS_FILE};
            getSettings().setArrayIfNotEmpty(KEYS.SUPPRESSION_FILE, suppressionFiles);
            engine = new Engine(getSettings());
            newAnalyzer().prepare(engine);

            // THEN rules from both files were loaded
            final int expectedSize = rulesInFirstFile + rulesInSecondFile + rulesInCoreFile;
            assertThat("Expected suppressions from both files", AbstractSuppressionAnalyzer.getRuleCount(engine), is(expectedSize));
        }

        @Test
        void testFailureToLocateSuppressionFileAnywhere() {
            getSettings().setString(Settings.KEYS.SUPPRESSION_FILE, "doesnotexist.xml");
            engine = new Engine(Mode.EVIDENCE_COLLECTION, getSettings());
            assertThrows(InitializationException.class, () -> newAnalyzer().prepare(engine));
        }
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
        engine = prepareSuppressions();
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
        engine = prepareSuppressions();
        return AbstractSuppressionAnalyzer.getRuleCount(engine);
    }

    private @NonNull Engine prepareSuppressions() throws InvalidSettingException, InitializationException {
        engine = new Engine(Mode.EVIDENCE_COLLECTION, getSettings());
        newAnalyzer().prepare(engine);
        return engine;
    }

    private @NonNull Engine prepareBaseSuppressionsOnly() throws InvalidSettingException, SuppressionParseException {
        engine = new Engine(Mode.EVIDENCE_COLLECTION, getSettings());
        newAnalyzer().loadPackagedBaseSuppressionData(engine);
        return engine;
    }

    private @NonNull Engine prepareHostedSuppressionsOnly() throws InvalidSettingException {
        engine = new Engine(Mode.EVIDENCE_COLLECTION, getSettings());
        newAnalyzer().loadHostedSuppressionBaseData(engine);
        return engine;
    }

    private @NonNull AbstractSuppressionAnalyzerImpl newAnalyzer() throws InvalidSettingException {
        final AbstractSuppressionAnalyzerImpl fileAnalyzer = new AbstractSuppressionAnalyzerImpl();
        fileAnalyzer.initialize(getSettings());
        Downloader.getInstance().configure(getSettings());
        return fileAnalyzer;
    }

    private @NonNull List<SuppressionRule> allRulesNotMarkedAsBase(List<SuppressionRule> baseRules) {
        return baseRules.stream().filter(r -> !r.isBase()).collect(Collectors.toList());
    }

    public static class AbstractSuppressionAnalyzerImpl extends AbstractSuppressionAnalyzer {

        @Override
        public void analyzeDependency(Dependency dependency, Engine engine) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public String getName() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public AnalysisPhase getAnalysisPhase() {
            throw new UnsupportedOperationException("Not supported yet.");
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
