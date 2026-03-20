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

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class YarnAuditAnalyzerIT extends BaseTest {

    @Nested
    class Classic {
        @Test
        void testAnalyzePackageYarnClassic() throws Exception {
            testAnalyzePackageYarn("yarn/yarn-classic-audit/yarn.lock");
        }
    }

    @Nested
    class Berry {
        @Test
        void testAnalyzePackage() throws Exception {
            testAnalyzePackageYarn("yarn/yarn-berry-audit/yarn.lock");
        }

        @Test
        void testAnalyzeWithBadYarnConfiguration() {
            IllegalStateException exception = assertThrows(IllegalStateException.class, () -> testAnalyzePackageYarn("yarn/yarn-berry-audit-bad-yarnrc/yarn.lock"));
            assertThat(exception.getMessage(), containsString("Unable to determine yarn version"));
            assertThat(exception.getCause().getMessage(), allOf(
                    containsString("exit value 1"),
                    containsString("bad-path-to-yarn.js")
            ));
        }

        @Test
        void testAnalyzeWithBadPackageManagerConfiguration() {
            IllegalStateException exception = assertThrows(IllegalStateException.class, () -> testAnalyzePackageYarn("yarn/yarn-berry-audit-bad-package-manager/yarn.lock"));
            assertThat(exception.getMessage(), containsString("Unable to determine yarn version"));
            assertThat(exception.getCause().getMessage(), allOf(
                    containsString("exit value 1"),
                    containsString("4.999.0-bad-version")
            ));
        }

        @Test
        void testAnalyzePackageNoVulnerability() throws Exception {
            try (Engine engine = new Engine(getSettings())) {
                analyze("yarn/yarn-berry-audit-no-vulnerability/yarn.lock", engine);
                assertEquals(0, engine.getDependencies().length, "No dependency should be identified");
            }
        }

        @Test
        void testAnalyzePackageExcludesDeprecations() throws Exception {
            try (Engine engine = new Engine(getSettings())) {
                analyze("yarn/yarn-berry-audit-no-deprecations/yarn.lock", engine);
                assertEquals(0, engine.getDependencies().length, "No dependency should be identified");
            }
        }
    }

    private void testAnalyzePackageYarn(String yarnLockFile) throws Exception {
        try (Engine engine = new Engine(getSettings())) {
            analyze(yarnLockFile, engine);
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
    }

    private void analyze(String yarnLockFile, Engine engine) throws InitializationException, AnalysisException {
        var analyzer = new YarnAuditAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize(getSettings());
        analyzer.prepare(engine);
        final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, yarnLockFile));
        analyzer.analyze(toScan, engine);
    }
}
