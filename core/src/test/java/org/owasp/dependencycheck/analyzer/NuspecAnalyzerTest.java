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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NuspecAnalyzerTest extends BaseTest {

    private NuspecAnalyzer instance;

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        instance = new NuspecAnalyzer();
        instance.initialize(getSettings());
        instance.prepare(null);
        instance.setEnabled(true);
    }

    @Test
    void testGetAnalyzerName() {
        assertEquals("Nuspec Analyzer", instance.getName());
    }

    @Test
    void testSupportsFileExtensions() {
        assertTrue(instance.accept(new File("test.nuspec")));
        assertFalse(instance.accept(new File("test.nupkg")));
    }

    @Test
    void testGetAnalysisPhaze() {
        assertEquals(AnalysisPhase.INFORMATION_COLLECTION, instance.getAnalysisPhase());
    }

    @Test
    void testNuspecAnalysis() throws Exception {

        File file = BaseTest.getResourceAsFile(this, "nuspec/test.nuspec");
        Dependency result = new Dependency(file);
        instance.analyze(result, null);

        assertEquals(NuspecAnalyzer.DEPENDENCY_ECOSYSTEM, result.getEcosystem());

        //checking the owner field
        assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("bobsmack"));

        //checking the author field
        assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("brianfox"));

        //checking the id field
        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("TestDepCheck"));

        //checking the title field
        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Test Package"));

        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("1.0.0"));
        assertEquals("1.0.0", result.getVersion());
        assertEquals("TestDepCheck", result.getName());
        assertEquals("TestDepCheck:1.0.0", result.getDisplayFileName());
    }
}
