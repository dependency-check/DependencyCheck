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

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
     * When the configured path points at a file that is not the govulncheck
     * executable the analyzer must disable itself; because the file exists it is
     * used as configured and no fallback to the PATH occurs.
     */
    @Test
    void testInvalidGovulncheckExecutable() {
        final String notAnExecutable = BaseTest.getResourceAsFile(this, "golang/vulncheck/go.mod").getAbsolutePath();
        getSettings().setString(Settings.KEYS.ANALYZER_GOLANG_VULNCHECK_PATH, notAnExecutable);
        final InitializationException thrown = assertThrows(InitializationException.class, () -> analyzer.prepare(null));
        assertNotNull(thrown.getMessage());
        assertFalse(analyzer.isEnabled());
    }

    /**
     * A configured path that does not exist is ignored with a warning and
     * `govulncheck` is looked up on the PATH, so the analyzer must end up in the
     * same state as one with no configured path - enabled when govulncheck is
     * installed, disabled when it is not.
     *
     * @throws Exception thrown if the temporary directory cannot be created or
     * the analyzer cannot be closed
     */
    @Test
    void testNonExistentGovulncheckPathFallsBackToPath() throws Exception {
        final boolean enabledWithoutConfiguredPath = prepareQuietly(analyzer);

        final File missing = new File(getSettings().getTempDirectory(), "no-such-govulncheck");
        getSettings().setString(Settings.KEYS.ANALYZER_GOLANG_VULNCHECK_PATH, missing.getAbsolutePath());
        final GolangVulncheckAnalyzer fallback = new GolangVulncheckAnalyzer();
        try {
            fallback.initialize(getSettings());
            fallback.setFilesMatched(true);
            assertEquals(enabledWithoutConfiguredPath, prepareQuietly(fallback),
                    "a configured path that does not exist should fall back to `govulncheck` on the PATH");
        } finally {
            fallback.close();
        }
    }

    /**
     * Prepares the analyzer, swallowing the initialization exception that is
     * thrown when govulncheck is not installed.
     *
     * @param toPrepare the analyzer to prepare
     * @return whether the analyzer is enabled after preparation
     */
    private static boolean prepareQuietly(GolangVulncheckAnalyzer toPrepare) {
        try {
            toPrepare.prepare(null);
        } catch (InitializationException e) {
            LOGGER.debug("govulncheck is not available", e);
        }
        return toPrepare.isEnabled();
    }

    private static void assertEqualsIgnoringNull(String expected, String actual) {
        if (actual != null) {
            assertTrue(expected.equals(actual), "expected version " + expected + " but was " + actual);
        }
    }
}
