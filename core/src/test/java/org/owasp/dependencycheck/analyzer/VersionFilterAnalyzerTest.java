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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.utils.Settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 *
 * @author Jeremy Long
 */
class VersionFilterAnalyzerTest extends BaseTest {

    /**
     * Test of getName method, of class VersionFilterAnalyzer.
     */
    @Test
    void testGetName() {
        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();
        String expResult = "Version Filter Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class VersionFilterAnalyzer.
     */
    @Test
    void testGetAnalysisPhase() {
        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();
        instance.initialize(getSettings());
        AnalysisPhase expResult = AnalysisPhase.POST_INFORMATION_COLLECTION3;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method, of class
     * VersionFilterAnalyzer.
     */
    @Test
    void testGetAnalyzerEnabledSettingKey() {
        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();
        instance.initialize(getSettings());
        String expResult = Settings.KEYS.ANALYZER_VERSION_FILTER_ENABLED;
        String result = instance.getAnalyzerEnabledSettingKey();
        assertEquals(expResult, result);
    }

    /**
     * Test of analyzeDependency method, of class VersionFilterAnalyzer.
     */
    @Test
    void testAnalyzeDependency() throws Exception {
        Dependency dependency = new Dependency();

        dependency.addEvidence(EvidenceType.VERSION, "util", "version", "33.3", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "version", "alpha", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "Implementation-Version", "1.2.3", Confidence.HIGHEST);

        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();
        instance.initialize(getSettings());

        instance.analyzeDependency(dependency, null);
        assertEquals(3, dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "pom", "version", "1.2.3", Confidence.HIGHEST);

        instance.analyzeDependency(dependency, null);
        assertEquals(4, dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "file", "version", "1.2.3", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(2, dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "Manifest", "Implementation-Version", "1.2.3", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(3, dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "nexus", "version", "1.2.3", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "version", "alpha", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(4, dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "central", "version", "1.2.3", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "version", "alpha", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(5, dependency.getEvidence(EvidenceType.VERSION).size());
    }

    /**
     * Test of analyzeDependency method, of class VersionFilterAnalyzer.
     */
    @Test
    void testAnalyzeDependencyFilePom() throws Exception {
        Dependency dependency = new Dependency();

        dependency.addEvidence(EvidenceType.VERSION, "util", "version", "33.3", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "version", "alpha", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "Implementation-Version", "1.2.3", Confidence.HIGHEST);

        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();
        instance.initialize(getSettings());

        instance.analyzeDependency(dependency, null);
        assertEquals(3, dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "pom", "version", "1.2.3", Confidence.HIGHEST);

        instance.analyzeDependency(dependency, null);
        assertEquals(4, dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "file", "version", "1.2.3", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(2, dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "nexus", "version", "1.2.3", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "version", "alpha", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(3, dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "central", "version", "1.2.3", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "version", "alpha", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(4, dependency.getEvidence(EvidenceType.VERSION).size());
    }

    /**
     * Test of analyzeDependency method, of class VersionFilterAnalyzer.
     */
    @Test
    void testAnalyzeDependencyFileManifest() throws Exception {
        Dependency dependency = new Dependency();

        dependency.addEvidence(EvidenceType.VERSION, "util", "version", "33.3", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "version", "alpha", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "Implementation-Version", "1.2.3", Confidence.HIGHEST);

        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();
        instance.initialize(getSettings());

        instance.analyzeDependency(dependency, null);
        assertEquals(3,  dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "Manifest", "Implementation-Version", "1.2.3", Confidence.HIGHEST);

        instance.analyzeDependency(dependency, null);
        assertEquals(4,  dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "file", "version", "1.2.3", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(2,  dependency.getEvidence(EvidenceType.VERSION).size());
    }

    /**
     * Test of analyzeDependency method, of class VersionFilterAnalyzer.
     */
    @Test
    void testAnalyzeDependencyPomManifest() throws Exception {
        Dependency dependency = new Dependency();

        dependency.addEvidence(EvidenceType.VERSION, "util", "version", "33.3", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "version", "alpha", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "Implementation-Version", "1.2.3", Confidence.HIGHEST);

        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();
        instance.initialize(getSettings());

        instance.analyzeDependency(dependency, null);
        assertEquals(3,  dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "pom", "version", "1.2.3", Confidence.HIGHEST);

        instance.analyzeDependency(dependency, null);
        assertEquals(4,  dependency.getEvidence(EvidenceType.VERSION).size());

        assertNull(dependency.getVersion());
        dependency.addEvidence(EvidenceType.VERSION, "Manifest", "Implementation-Version", "1.2.3", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals("1.2.3", dependency.getVersion());
        assertEquals(2,  dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "nexus", "version", "1.2.3", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "version", "alpha", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(3,  dependency.getEvidence(EvidenceType.VERSION).size());

        dependency.addEvidence(EvidenceType.VERSION, "central", "version", "1.2.3", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "other", "version", "alpha", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(4,  dependency.getEvidence(EvidenceType.VERSION).size());
    }
}
