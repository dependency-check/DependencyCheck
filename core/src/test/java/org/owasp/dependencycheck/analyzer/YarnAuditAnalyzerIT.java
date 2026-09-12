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
 * Copyright (c) 2021 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.lang3.SystemUtils;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;
import static org.owasp.dependencycheck.analyzer.YarnAuditAnalyzer.YARN_ENV_IGNORE_PATH;

class YarnAuditAnalyzerIT extends BaseTest {

    private Engine engine;
    private YarnAuditAnalyzer analyzer;

    @BeforeEach
    void prepareAnalyzer() {
        engine = new Engine(getSettings());
        analyzer = assertDoesNotThrow(() -> prepareAnalyzer(engine),  "Yarn Analyzer could not be initialized - yarn possibly not available on path for tests");
    }

    @AfterEach
    void cleanup() {
        if (engine != null) {
            engine.close();
        }
    }

    @Nested
    class YarnUnsupported {
        @Test
        void testYarnClassicUnsupported() throws Exception {
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(YarnAuditAnalyzerIT.this, "yarn/yarn-classic-audit/yarn.lock"));
            analyzer.analyze(toScan, engine);
            assertEquals(0, engine.getDependencies().length, "No dependencies should be identified");
        }

        @Test
        void testYarnBerryUnsupported() throws Exception {
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(YarnAuditAnalyzerIT.this, "yarn/yarn-berry-audit-unsupported/yarn.lock"));
            analyzer.analyze(toScan, engine);
            assertEquals(0, engine.getDependencies().length, "No dependencies should be identified");
        }
    }

    @Nested
    class YarnConfiguration {
        @Test
        void testAnalyzeWithBadYarnConfiguration() {
            IllegalStateException exception = assertThrows(IllegalStateException.class, () -> testAnalyzeForUglifyJs("yarn/yarn-berry-audit-bad-yarnrc/yarn.lock"));
            assertThat(exception.getMessage(), containsString("Unable to determine yarn version"));
            assertThat(exception.getCause().getMessage(), allOf(
                    containsString("exit value 1"),
                    containsString("Couldn't parse \"bad-value\" as a boolean")
            ));
        }

        @ParameterizedTest
        @NullSource
        @ValueSource(strings = {" ", "1", "true"})
        void testAnalyzeIgnoresBadYarnPath(String envValue) throws Exception {
            try (MockedStatic<SystemUtils> systemMock = mockStatic(SystemUtils.class)) {
                systemMock.when(() -> SystemUtils.getEnvironmentVariable(YARN_ENV_IGNORE_PATH, null)).thenReturn(envValue);

                final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(YarnAuditAnalyzerIT.this, "yarn/yarn-berry-audit-bad-path/yarn.lock"));
                analyzer.analyze(toScan, engine);
                assertEquals(0, engine.getDependencies().length, "No dependency should be identified");
            }
        }

        @ParameterizedTest
        @ValueSource(strings = {"0", "false"})
        void testAnalyzeAllowsYarnPath(String envValue) {
            try (MockedStatic<SystemUtils> systemMock = mockStatic(SystemUtils.class)) {
                systemMock.when(() -> SystemUtils.getEnvironmentVariable(YARN_ENV_IGNORE_PATH, null)).thenReturn(envValue);

                final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(YarnAuditAnalyzerIT.this, "yarn/yarn-berry-audit-bad-path/yarn.lock"));
                IllegalStateException exception = assertThrows(IllegalStateException.class, () -> analyzer.analyze(toScan, engine));
                assertThat(exception.getMessage(), containsString("Unable to determine yarn version"));
                assertThat(exception.getCause().getMessage(), allOf(
                        containsString("no such file or directory"), // yarnrc yarnPath points to non-existent path so we can detect usage
                        containsString("does-not-exist/yarn.js")
                ));
            }
        }

        @Test
        void testAnalyzeWithBadPackageManagerConfiguration() {
            IllegalStateException exception = assertThrows(IllegalStateException.class, () -> testAnalyzeForUglifyJs("yarn/yarn-berry-audit-bad-package-manager/yarn.lock"));
            assertThat(exception.getMessage(), containsString("Unable to determine yarn version"));
            assertThat(exception.getCause().getMessage(), allOf(
                    containsString("exit value 1"),
                    containsString("4.999.0-bad-version")
            ));
        }
    }

    @Nested
    class SuccessfulAnalysis {
        @Test
        void testAnalyzePackage() throws Exception {
            testAnalyzeForUglifyJs("yarn/yarn-berry-audit/yarn.lock");
        }

        @Test
        void testAnalyzePackageNoVulnerability() throws Exception {
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(YarnAuditAnalyzerIT.this, "yarn/yarn-berry-audit-no-vulnerability/yarn.lock"));
            analyzer.analyze(toScan, engine);
            assertEquals(0, engine.getDependencies().length, "No dependency should be identified");
        }

        @Test
        void testAnalyzePackageExcludesDeprecations() throws Exception {
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(YarnAuditAnalyzerIT.this, "yarn/yarn-berry-audit-no-deprecations/yarn.lock"));
            analyzer.analyze(toScan, engine);
            assertEquals(0, engine.getDependencies().length, "No dependency should be identified");
        }
    }

    private void testAnalyzeForUglifyJs(String yarnLockFile) throws Exception {
        final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, yarnLockFile));
        analyzer.analyze(toScan, engine);
        assertTrue(1 < engine.getDependencies().length, "More than 1 dependency should be identified");
        boolean found = false;
        for (Dependency result : engine.getDependencies()) {
            if ("yarn.lock?uglify-js".equals(result.getFileName())) {
                found = true;
                assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("uglify-js"));
                assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("uglify-js"));
                assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("2.4.24"), "Unable to find version 2.4.24: " + result.getEvidence(EvidenceType.VERSION).toString());
                assertTrue(result.isVirtual());
            }
        }
        assertTrue(found, "Uglify was not found");
    }

    private @NonNull YarnAuditAnalyzer prepareAnalyzer(Engine engine) throws InitializationException {
        var analyzer = new YarnAuditAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize(getSettings());
        analyzer.prepare(engine);
        return analyzer;
    }
}
