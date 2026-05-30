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
package org.owasp.dependencycheck.data.update;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

class RetireJSDataSourceTest extends BaseTest {
    private static final String TEST_RETIRE_JS_REPOSITORY_FILE = "retirejs/jsrepository.json";

    private RetireJSDataSource dataSource;
    private Engine engine;

    @BeforeEach
    public void createEngine() {
        dataSource = new RetireJSDataSource();
        engine = new Engine(Engine.Mode.EVIDENCE_COLLECTION, getSettings());
    }

    @AfterEach
    void closeEngine() {
        if (engine != null) {
            dataSource.purge(engine);
            engine.close();
        }
    }

    @Nested
    class Update {
        @Test
        void doesNothingIfRetireJsDisabled() throws Exception {
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, false);
            dataSource.update(engine);
            assertNoCachedRetireJs();
        }

        @Test
        void loadsRemoteIfEmptyWithAutoUpdateDisabled() throws Exception {
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            dataSource.update(engine);
            assertCachedRetireJs();
        }

        @Test
        void doesNothingIfPresentAndAutoUpdateDisabled() throws Exception {
            dataSource.update(engine);

            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_FORCEUPDATE, false);

            // try again with repo present; but with a URL that would fail if invoked
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, testRepositoryFileUrl().replace(TEST_RETIRE_JS_REPOSITORY_FILE, "doesnt-exist/" + TEST_RETIRE_JS_REPOSITORY_FILE));
            dataSource.update(engine);
        }

        @Test
        void failsIfRemoteRetireJsRepoNotFound() throws Exception {
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, "file:///does-not-exist.xml");
            var ex = assertThrows(UpdateException.class, () -> dataSource.update(engine));
            assertThat(ex.getMessage(), containsString("Failed to initialize the RetireJS repo"));
            assertThat(ExceptionUtils.getRootCause(ex), instanceOf(NoSuchFileException.class));
            assertNoCachedRetireJs();
        }

        @Test
        void failsIfUrlDoesntIncludeAFileName() {
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, "https://valid.url.but.no.file/");
            var ex = assertThrowsExactly(UpdateException.class, () -> dataSource.update(engine));
            assertThat(ex.getMessage(), containsString("Unable to determine the local location to cache"));
            assertThat(ex.getCause(), instanceOf(InvalidSettingException.class));
            assertThat(ex.getCause().getMessage(), containsString("RetireJS URL must imply a filename"));
        }

        @Test
        void failsIfUrlIsMalformed() {
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, "bad-url");
            var ex = assertThrowsExactly(UpdateException.class, () -> dataSource.update(engine));
            assertThat(ex.getMessage(), containsString("Invalid URL for RetireJS repository (bad-url)"));
            assertThat(ex.getCause(), instanceOf(MalformedURLException.class));
        }

        @Test
        void loadsRemoteRetireJsIfEnabledAndForced() throws Exception {
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_FORCEUPDATE, true);
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, testRepositoryFileUrl());
            dataSource.update(engine);

            // try again with repo present; but with a URL that fails when invoked
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, testRepositoryFileUrl().replace(TEST_RETIRE_JS_REPOSITORY_FILE, "doesnt-exist/" + TEST_RETIRE_JS_REPOSITORY_FILE));
            var ex = assertThrowsExactly(UpdateException.class, () -> dataSource.update(engine));
            assertThat(ExceptionUtils.getRootCause(ex), instanceOf(NoSuchFileException.class));
        }

        @Test
        void loadsRemoteRetireJsIfEnabledWithAutoUpdate() throws Exception {
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, testRepositoryFileUrl());
            dataSource.update(engine);
            assertThat(Files.readString(cachedRepoFile()), is(testRepositoryFileContent()));
            assertThat(Files.exists(cachedRepoFileProperties()), is(true));
        }

        @Test
        void doesNothingIfRemoteRetireJsIsNotStale() throws Exception {
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, testRepositoryFileUrl());
            getSettings().setInt(Settings.KEYS.ANALYZER_RETIREJS_REPO_VALID_FOR_HOURS, 1);
            dataSource.update(engine);

            // Update again immediately
            String firstUpdateProperties = Files.readString(cachedRepoFileProperties());
            FileTime firstUpdatePropertiesModified = Files.getLastModifiedTime(cachedRepoFileProperties());
            dataSource.update(engine);

            assertThat(Files.readString(cachedRepoFileProperties()), is(firstUpdateProperties));
            assertThat(Files.getLastModifiedTime(cachedRepoFileProperties()), is(firstUpdatePropertiesModified));
        }

        @Test
        void reloadsRemoteRetireJsIfStale() throws Exception {
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, testRepositoryFileUrl());
            getSettings().setInt(Settings.KEYS.ANALYZER_RETIREJS_REPO_VALID_FOR_HOURS, 0);
            dataSource.update(engine);

            // Reset to force an update
            Files.writeString(cachedRepoFile(), "stale content");

            dataSource.update(engine);
            assertThat(Files.readString(cachedRepoFile()), not("stale content"));
        }
    }

    @Nested
    class Purge {
        @Test
        void purgeRemovesCachedFiles() throws Exception {
            getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, testRepositoryFileUrl());
            dataSource.update(engine);

            assertThat(Files.exists(cachedRepoFile()), is(true));
            dataSource.purge(engine);
            assertThat(Files.exists(cachedRepoFile()), is(false));
        }

        @Test
        void doesNothingIfNoCachedFile() throws Exception {
            dataSource.purge(engine);
            assertThat(Files.exists(cachedRepoFile()), is(false));
        }

        @Test
        void doesNothingIfUrlIsMalformed() {
            getSettings().setString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, "bad-url");
            dataSource.purge(engine);
        }
    }

    private @NonNull Path cachedRepoFile() throws UpdateException {
        return dataSource.validatedRepoFile().toPath();
    }

    private @NonNull Path cachedRepoFileProperties() throws UpdateException {
        return Path.of(cachedRepoFile() + ".properties");
    }

    private @NonNull String testRepositoryFileUrl() {
        return BaseTest.getResourceAsUrlString(this, TEST_RETIRE_JS_REPOSITORY_FILE);
    }

    private @NonNull String testRepositoryFileContent() {
        return BaseTest.getResourceAsContentString(this, TEST_RETIRE_JS_REPOSITORY_FILE);
    }

    private void assertNoCachedRetireJs() throws UpdateException {
        assertThat("RetireJS repo file should not exist", dataSource.validatedRepoFile().exists(), is(false));
    }

    private void assertCachedRetireJs() throws UpdateException {
        assertThat("RetireJS repo file should exist", dataSource.validatedRepoFile().exists(), is(true));
    }
}
