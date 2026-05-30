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
 * Copyright (c) 2026 Chad Wilson. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.json.JSONException;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.update.RetireJSDataSource;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

import java.nio.file.NoSuchFileException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RetireJsAnalyzerTest extends BaseTest {
    private static final String TEST_RETIRE_JS_REPOSITORY_FILE = "retirejs/jsrepository.json";

    private RetireJsAnalyzer analyzer;
    private Engine engine;

    @BeforeEach
    void settings() {
        getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_FORCEUPDATE, false);
        getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, testRepositoryFileUrl());
    }
    
    @AfterEach
    void cleanUp() {
        if (engine != null) {
            new RetireJSDataSource().purge(engine);
            engine.close();
        }
    }

    private String testRepositoryFileUrl() {
        return BaseTest.getResourceAsUrlString(this, TEST_RETIRE_JS_REPOSITORY_FILE);
    }

    @Nested
    class RepositoryLoading {

        @Test
        void loadsRemoteIfEmptyWithAutoUpdateDisabled() throws Exception {
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            prepareRetireJs();
            assertThat(analyzer.knownLibraryCountFor("retire-example-0.0.1.js").orElseThrow(), is(1));
        }

        @Test
        void loadsRemoteIfPresentAndForced() throws Exception {
            prepareRetireJs();

            // try again with repo present; but with a URL that will fail when invoked so we know it tried
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_FORCEUPDATE, true);
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, testRepositoryFileUrl().replace(TEST_RETIRE_JS_REPOSITORY_FILE, "doesnt-exist/" + TEST_RETIRE_JS_REPOSITORY_FILE));

            var ex = assertThrows(InitializationException.class, RetireJsAnalyzerTest.this::prepareRetireJs);
            assertThat(ex.getMessage(), containsString("Failed to initialize the RetireJS repo"));
            assertThat(ExceptionUtils.getRootCause(ex), instanceOf(NoSuchFileException.class));
        }

        @Test
        void doesNothingIfPresentAndAutoUpdateDisabled() throws Exception {
            prepareRetireJs();

            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_FORCEUPDATE, false);

            // try again with repo present; but with a URL that would fail if invoked
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, testRepositoryFileUrl().replace(TEST_RETIRE_JS_REPOSITORY_FILE, "doesnt-exist/" + TEST_RETIRE_JS_REPOSITORY_FILE));
            prepareRetireJs();
        }

        @Test
        void failsIfRemoteRetireJsRepoNotFound() {
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, "file:///does-not-exist.xml");
            var ex = assertThrows(InitializationException.class, RetireJsAnalyzerTest.this::prepareRetireJs);
            assertThat(ex.getMessage(), containsString("Failed to initialize the RetireJS repo"));
            assertThat(ExceptionUtils.getRootCause(ex), instanceOf(NoSuchFileException.class));
            assertThat(analyzer.isEnabled(), is(false));
        }

        @Test
        void failsIfRemoteRetireJsCannotBeParsed() {
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, BaseTest.getResourceAsUrlString(this, "retirejs/jsrepository-invalid.json"));
            var ex = assertThrows(InitializationException.class, RetireJsAnalyzerTest.this::prepareRetireJs);
            assertThat(ex.getMessage(), containsString("Failed to initialize the RetireJS repo"));
            assertThat(ExceptionUtils.getRootCause(ex), instanceOf(JSONException.class));
            assertThat(analyzer.isEnabled(), is(false));
        }

        @Test
        void prefersRemoteRetireJsIfEnabled() throws Exception {
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, testRepositoryFileUrl());
            prepareRetireJs();
            assertThat(analyzer.knownLibraryCountFor("retire-example-0.0.1.js").orElseThrow(), is(1));
        }
    }

    private void prepareRetireJs() throws InvalidSettingException, InitializationException {
        engine = new Engine(Engine.Mode.EVIDENCE_COLLECTION, getSettings());
        analyzer = newAnalyzer();
        analyzer.prepareFileTypeAnalyzer(engine);
    }

    private @NonNull RetireJsAnalyzer newAnalyzer() throws InvalidSettingException {
        final RetireJsAnalyzer fileAnalyzer = new RetireJsAnalyzer();
        fileAnalyzer.initialize(getSettings());
        Downloader.getInstance().configure(getSettings());
        return fileAnalyzer;
    }
}