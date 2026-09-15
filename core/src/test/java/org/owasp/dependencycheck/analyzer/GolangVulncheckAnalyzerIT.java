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
 * Copyright (c) 2026 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration tests for GolangVulncheckAnalyzer. These exercise the real
 * {@code govulncheck} tool and are skipped when it (or {@code go}) is not
 * installed. To run locally ensure {@code go} and {@code govulncheck} are on the
 * PATH, or set the {@code analyzer.golang.vulncheck.path} property.
 *
 * @author Srinivas Chippagiri
 */
class GolangVulncheckAnalyzerIT extends BaseDBTestCase {

    private static final Logger LOGGER = LoggerFactory.getLogger(GolangVulncheckAnalyzerIT.class);

    private GolangVulncheckAnalyzer analyzer;

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_GOLANG_VULNCHECK_ENABLED, true);
        analyzer = new GolangVulncheckAnalyzer();
        analyzer.initialize(getSettings());
        analyzer.setFilesMatched(true);
    }

    @AfterEach
    @Override
    public void tearDown() throws Exception {
        if (analyzer != null) {
            analyzer.close();
            analyzer = null;
        }
        super.tearDown();
    }

    /**
     * Runs govulncheck against a module that calls a known-vulnerable
     * {@code golang.org/x/text} v0.3.5 symbol and verifies the reachable
     * vulnerability (GO-2021-0113 / CVE-2021-38561) is reported.
     *
     * @throws DatabaseException thrown when the database cannot be opened
     */
    @Test
    void testAnalysis() throws DatabaseException {
        try (Engine engine = new Engine(getSettings())) {
            engine.openDatabase();
            analyzer.prepare(engine);

            final String resource = "golang/vulncheck/go.mod";
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, resource));
            analyzer.analyze(toScan, engine);

            final Dependency[] dependencies = engine.getDependencies();
            assertTrue(dependencies.length > 0, "govulncheck should have reported at least one vulnerable module");

            boolean foundTextModule = false;
            boolean foundVulnerability = false;
            for (Dependency d : dependencies) {
                if ("golang.org/x/text".equals(d.getName())) {
                    foundTextModule = true;
                    assertTrue(d.isVirtual());
                    assertEqualsIgnoringNull("0.3.5", d.getVersion());
                    assertTrue(GolangVulncheckAnalyzer.DEPENDENCY_ECOSYSTEM.equals(d.getEcosystem()));
                }
                for (Vulnerability v : d.getVulnerabilities()) {
                    final String name = v.getName();
                    // depending on the local DB the finding may be reused from NVD (CVE id)
                    // or synthesized from the govulncheck advisory (GO id)
                    if ("GO-2021-0113".equals(name) || "CVE-2021-38561".equals(name)) {
                        foundVulnerability = true;
                    }
                }
            }
            assertTrue(foundTextModule, "expected a dependency for golang.org/x/text");
            assertTrue(foundVulnerability, "expected GO-2021-0113 / CVE-2021-38561 to be reported for x/text 0.3.5");
        } catch (InitializationException | AnalysisException e) {
            LOGGER.warn("Skipping GolangVulncheckAnalyzerIT; ensure go and govulncheck are installed "
                    + "(or set the \"analyzer.golang.vulncheck.path\" property).", e);
            assumeTrue(false, "govulncheck may not be installed: " + e);
        }
    }

    /**
     * When govulncheck is misconfigured (the configured path is not a valid
     * executable) the analyzer must disable itself.
     */
    @Test
    void testInvalidGovulncheckExecutable() {
        final String path = BaseTest.getResourceAsFile(this, "golang/vulncheck/go.mod").getAbsolutePath();
        getSettings().setString(Settings.KEYS.ANALYZER_GOLANG_VULNCHECK_PATH, path);
        analyzer.initialize(getSettings());
        try {
            analyzer.prepare(null);
        } catch (InitializationException e) {
            assertNotNull(e);
        } finally {
            assertFalse(analyzer.isEnabled());
        }
    }

    private static void assertEqualsIgnoringNull(String expected, String actual) {
        if (actual != null) {
            assertTrue(expected.equals(actual), "expected version " + expected + " but was " + actual);
        }
    }
}
