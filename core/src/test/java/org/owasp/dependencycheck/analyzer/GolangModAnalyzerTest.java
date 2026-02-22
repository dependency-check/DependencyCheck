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
 * Copyright (c) 2019 Matthijs van den Bos. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for GolangModAnalyzer.
 *
 * @author Matthijs van den Bos
 */
class GolangModAnalyzerTest extends BaseTest {

    private GolangModAnalyzer analyzer;
    private Engine engine;

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED, false);
        //hack fix because IDE is not correctly pulling in path
        if (getSettings().getString(Settings.KEYS.ANALYZER_GOLANG_PATH) == null) {
            File go = new File("/usr/local/bin/go");
            if (go.isFile() && go.canExecute()) {
                getSettings().setString(Settings.KEYS.ANALYZER_GOLANG_PATH, "/usr/local/bin/go");
            }
        }
        analyzer = new GolangModAnalyzer();
        engine = new Engine(this.getSettings());
        analyzer.initialize(getSettings());
        analyzer.setFilesMatched(true);
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
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
    void testName() {
        assertEquals("Golang Mod Analyzer",
                analyzer.getName(),
                "Analyzer name wrong.");
    }

    @Test
    void testSupportsFiles() {
        assertThat(analyzer.accept(new File("go.mod")), is(true));
    }

    @Test
    void testGoMod() throws AnalysisException, InitializationException {
        analyzer.prepare(engine);
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "golang/go.mod"));
        analyzer.analyze(result, engine);

        assertEquals(7, engine.getDependencies().length);

        boolean found = false;
        for (Dependency d : engine.getDependencies()) {
            if ("gitea".equals(d.getName())) {
                found = true;
                assertEquals("1.5.0", d.getVersion());
                assertEquals("github.com/go-gitea/gitea:1.5.0", d.getDisplayFileName());
                assertEquals(GolangModAnalyzer.DEPENDENCY_ECOSYSTEM, d.getEcosystem());
                assertTrue(d.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("go-gitea"));
                assertTrue(d.getEvidence(EvidenceType.PRODUCT).toString().toLowerCase().contains("gitea"));
                assertTrue(d.getEvidence(EvidenceType.VERSION).toString().toLowerCase().contains("1.5.0"));
            }
        }
        assertTrue(found, "Expected to find gitea/gitea");
    }
}
