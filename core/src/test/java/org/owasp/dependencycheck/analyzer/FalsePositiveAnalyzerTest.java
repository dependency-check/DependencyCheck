/*
 * Copyright 2014 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import org.owasp.dependencycheck.utils.Settings;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeBuilder;
import us.springett.parsers.cpe.values.Part;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class FalsePositiveAnalyzerTest extends BaseTest {

    /**
     * A CPE builder object.
     */
    private final CpeBuilder builder = new CpeBuilder();

    /**
     * Test of getName method, of class FalsePositiveAnalyzer.
     */
    @Test
    void testGetName() {
        FalsePositiveAnalyzer instance = new FalsePositiveAnalyzer();
        String expResult = "False Positive Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class FalsePositiveAnalyzer.
     */
    @Test
    void testGetAnalysisPhase() {
        FalsePositiveAnalyzer instance = new FalsePositiveAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.POST_IDENTIFIER_ANALYSIS;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method, of class
     * FalsePositiveAnalyzer.
     */
    @Test
    void testGetAnalyzerEnabledSettingKey() {
        FalsePositiveAnalyzer instance = new FalsePositiveAnalyzer();
        String expResult = Settings.KEYS.ANALYZER_FALSE_POSITIVE_ENABLED;
        String result = instance.getAnalyzerEnabledSettingKey();
        assertEquals(expResult, result);
    }

    /**
     * Test of analyzeDependency method, of class FalsePositiveAnalyzer.
     */
    @Test
    void testAnalyzeDependency() throws Exception {
        Dependency dependency = new Dependency();
        dependency.setFileName("pom.xml");
        dependency.setFilePath("pom.xml");
        Cpe cpe = builder.part(Part.APPLICATION).vendor("file").product("file").version("1.2.1").build();
        CpeIdentifier id = new CpeIdentifier(cpe, "http://some.org/url", Confidence.HIGHEST);
        dependency.addVulnerableSoftwareIdentifier(id);
        Engine engine = null;
        FalsePositiveAnalyzer instance = new FalsePositiveAnalyzer();
        int before = dependency.getVulnerableSoftwareIdentifiers().size();
        instance.analyze(dependency, engine);
        int after = dependency.getVulnerableSoftwareIdentifiers().size();
        assertTrue(before > after);
    }

    /**
     * Test of removeBadMatches method, of class FalsePositiveAnalyzer.
     */
    @Test
    void testRemoveBadMatches() throws Exception {
        Dependency dependency = new Dependency();
        dependency.setFileName("some.jar");
        dependency.setFilePath("some.jar");
        Cpe cpe = builder.part(Part.APPLICATION).vendor("m-core").product("m-core").build();
        CpeIdentifier id = new CpeIdentifier(cpe, Confidence.HIGHEST);
        dependency.addVulnerableSoftwareIdentifier(id);

        assertEquals(1, dependency.getVulnerableSoftwareIdentifiers().size());

        FalsePositiveAnalyzer instance = new FalsePositiveAnalyzer();
        instance.removeBadMatches(dependency);

        assertEquals(0, dependency.getVulnerableSoftwareIdentifiers().size());
        dependency.addVulnerableSoftwareIdentifier(id);
        dependency.addEvidence(EvidenceType.PRODUCT, "test", "name", "m-core", Confidence.HIGHEST);

        instance.removeBadMatches(dependency);
        assertEquals(1, dependency.getVulnerableSoftwareIdentifiers().size());
    }
}
