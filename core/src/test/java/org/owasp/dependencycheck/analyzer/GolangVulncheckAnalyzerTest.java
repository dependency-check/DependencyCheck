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
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Unit tests for GolangVulncheckAnalyzer.
 *
 * @author Srinivas Chippagiri
 */
class GolangVulncheckAnalyzerTest extends BaseTest {

    private GolangVulncheckAnalyzer analyzer;

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        // the analyzer is disabled by default; enable it so accept() reports matches
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

    @Test
    void testGetName() {
        assertThat(analyzer.getName(), is("Golang Vulncheck Analyzer"));
    }

    @Test
    void testGetAnalysisPhase() {
        assertThat(analyzer.getAnalysisPhase(), is(AnalysisPhase.PRE_INFORMATION_COLLECTION));
    }

    @Test
    void testSupportsFiles() {
        assertThat(analyzer.accept(new File("go.mod")), is(true));
        assertThat(analyzer.accept(new File("go.sum")), is(false));
    }
}
