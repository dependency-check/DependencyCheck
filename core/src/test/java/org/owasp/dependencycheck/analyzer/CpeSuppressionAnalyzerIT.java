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

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Testing the CPE suppression analyzer.
 *
 * @author Jeremy Long
 */
class CpeSuppressionAnalyzerIT extends BaseDBTestCase {

    /**
     * Test of getName method, of class CpeSuppressionAnalyzer.
     */
    @Test
    void testGetName() {
        CpeSuppressionAnalyzer instance = new CpeSuppressionAnalyzer();
        instance.initialize(getSettings());
        String expResult = "Cpe Suppression Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class CpeSuppressionAnalyzer.
     */
    @Test
    void testGetAnalysisPhase() {
        CpeSuppressionAnalyzer instance = new CpeSuppressionAnalyzer();
        instance.initialize(getSettings());
        AnalysisPhase expResult = AnalysisPhase.POST_IDENTIFIER_ANALYSIS;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of analyze method, of class CpeSuppressionAnalyzer.
     */
    @Test
    void testAnalyze() throws Exception {

        File file = BaseTest.getResourceAsFile(this, "maven-lib/commons-fileupload-1.2.1.jar");
        File suppression = BaseTest.getResourceAsFile(this, "commons-fileupload-1.2.1.suppression.xml");
        getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        Dependency dependency;
        int cveSize = 0;
        int cpeSize = 0;
        try (Engine engine = new Engine(getSettings())) {
            engine.scan(file);
            engine.analyzeDependencies();
            dependency = getDependency(engine, file);
            cveSize = dependency.getVulnerabilities().size();
            cpeSize = dependency.getVulnerableSoftwareIdentifiers().size();
            assertTrue(cveSize > 0);
            assertTrue(cpeSize > 0);
        }
        getSettings().setString(Settings.KEYS.SUPPRESSION_FILE, suppression.getAbsolutePath());
        try (Engine engine = new Engine(getSettings())) {
            CpeSuppressionAnalyzer instance = new CpeSuppressionAnalyzer();
            instance.initialize(getSettings());
            instance.prepare(engine);
            instance.analyze(dependency, engine);

            cpeSize -= 1;
            assertEquals(cveSize, dependency.getVulnerabilities().size());
            assertEquals(cpeSize, dependency.getVulnerableSoftwareIdentifiers().size());
        }
    }

    /**
     * Retrieves a specific dependency from the engine.
     *
     * @param engine the engine
     * @param file the dependency to retrieve
     * @return the dependency
     */
    private Dependency getDependency(Engine engine, File file) {
        for (Dependency d : engine.getDependencies()) {
            if (d.getFileName().equals(file.getName())) {
                return d;
            }
        }
        return null;
    }
}
