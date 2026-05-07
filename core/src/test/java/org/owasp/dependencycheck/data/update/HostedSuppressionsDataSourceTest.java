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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

class HostedSuppressionsDataSourceTest extends BaseTest {

    private static final String TEST_SUPPRESSIONS_FILE = "suppressions.xml";

    private HostedSuppressionsDataSource dataSource;
    private Engine engine;

    @BeforeEach
    public void createEngine() {
        dataSource = new HostedSuppressionsDataSource();
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
        void doesNothingIfRemoteHostedSuppressionsDisabled() throws Exception {
            getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, false);
            dataSource.update(engine);
            assertNoCachedHostedSuppressions();
        }

        @Test
        void doesNothingIfNoSuppressionAnalyzersEnabled() throws Exception {
            getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.ANALYZER_VULNERABILITY_SUPPRESSION_ENABLED, false);
            getSettings().setBoolean(Settings.KEYS.ANALYZER_CPE_SUPPRESSION_ENABLED, false);
            dataSource.update(engine);
            assertNoCachedHostedSuppressions();
        }

        @Test
        void doesNothingIfAutoUpdateDisabled() throws Exception {
            getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_FORCEUPDATE, false);
            dataSource.update(engine);
            assertNoCachedHostedSuppressions();
        }

        @Test
        void ignoresHostedSuppressionsIfRemoteHostedSuppressionsFail() throws Exception {
            getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            getSettings().setString(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, "file:///does-not-exist.xml");
            dataSource.update(engine);
            assertNoCachedHostedSuppressions();
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void failsIfSuppressionsUrlDoesntIncludeAFileNameRegardlessOfEnabledState(boolean hostedSuppressionsEnabled) throws Exception {
            getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, hostedSuppressionsEnabled);
            getSettings().setString(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, "https://valid.url.but.no.file/");
            var ex = assertThrowsExactly(UpdateException.class, () -> dataSource.update(engine));
            assertThat(ex.getMessage(), containsString("Unable to determine the local location to cache hosted suppressions"));
            assertThat(ex.getCause(), instanceOf(InvalidSettingException.class));
            assertThat(ex.getCause().getMessage(), containsString("Hosted Suppression URL must imply a filename"));
        }

        @Test
        void failsIfSuppressionsUrlIsMalformed() {
            getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setString(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, "bad-url");
            var ex = assertThrowsExactly(UpdateException.class, () -> dataSource.update(engine));
            assertThat(ex.getMessage(), containsString("Unable to determine the local location to cache hosted suppressions"));
            assertThat(ex.getCause(), instanceOf(InvalidSettingException.class));
            assertThat(ex.getCause().getMessage(), containsString("Invalid URL for Hosted Suppressions"));
        }

        @Test
        void loadsRemoteHostedSuppressionsIfEnabledAndForced() throws Exception {
            getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_FORCEUPDATE, true);
            getSettings().setString(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, testSuppressionsFileUrl());
            dataSource.update(engine);
            assertThat(Files.readString(cachedRepoFile()), is(testSuppressionsFileContent()));
            assertThat(Files.exists(cachedRepoFileProperties()), is(true));
        }

        @Test
        void loadsRemoteHostedSuppressionsIfEnabledWithAutoUpdate() throws Exception {
            getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            getSettings().setString(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, testSuppressionsFileUrl());
            dataSource.update(engine);
            assertThat(Files.readString(cachedRepoFile()), is(testSuppressionsFileContent()));
            assertThat(Files.exists(cachedRepoFileProperties()), is(true));
        }

        @Test
        void doesNothingIfRemoteHostedSuppressionsIsNotStale() throws Exception {
            getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            getSettings().setString(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, testSuppressionsFileUrl());
            getSettings().setInt(Settings.KEYS.HOSTED_SUPPRESSIONS_VALID_FOR_HOURS, 1);
            dataSource.update(engine);

            // Update again immediately
            String firstUpdateProperties = Files.readString(cachedRepoFileProperties());
            FileTime firstUpdatePropertiesModified = Files.getLastModifiedTime(cachedRepoFileProperties());
            dataSource.update(engine);

            assertThat(Files.readString(cachedRepoFileProperties()), is(firstUpdateProperties));
            assertThat(Files.getLastModifiedTime(cachedRepoFileProperties()), is(firstUpdatePropertiesModified));
        }

        @Test
        void reloadsRemoteHostedSuppressionsIfStale() throws Exception {
            getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            getSettings().setString(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, testSuppressionsFileUrl());
            getSettings().setInt(Settings.KEYS.HOSTED_SUPPRESSIONS_VALID_FOR_HOURS, 0);
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
            getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
            getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            getSettings().setString(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, testSuppressionsFileUrl());
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
        void doesNothingIfSuppressionsUrlIsMalformed() {
            getSettings().setString(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, "bad-url");
            dataSource.purge(engine);
        }
    }

    private @NonNull Path cachedRepoFile() throws IOException {
        return dataSource.validatedRepoFile().toPath();
    }

    private @NonNull Path cachedRepoFileProperties() throws IOException {
        return Path.of(cachedRepoFile() + ".properties");
    }

    private @NonNull String testSuppressionsFileUrl() {
        return BaseTest.getResourceAsUrlString(this, TEST_SUPPRESSIONS_FILE);
    }

    private @NonNull String testSuppressionsFileContent() {
        return BaseTest.getResourceAsContentString(this, TEST_SUPPRESSIONS_FILE);
    }

    private void assertNoCachedHostedSuppressions() throws IOException {
        assertThat("hosted suppression repo file should not exist", dataSource.validatedRepoFile().exists(), is(false));
    }
}
