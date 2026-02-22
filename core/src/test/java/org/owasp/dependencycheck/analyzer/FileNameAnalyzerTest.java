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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class FileNameAnalyzerTest extends BaseTest {

    /**
     * Test of getName method, of class FileNameAnalyzer.
     */
    @Test
    void testGetName() {
        FileNameAnalyzer instance = new FileNameAnalyzer();
        String expResult = "File Name Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class FileNameAnalyzer.
     */
    @Test
    void testGetAnalysisPhase() {
        FileNameAnalyzer instance = new FileNameAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.INFORMATION_COLLECTION;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of analyze method, of class FileNameAnalyzer.
     */
    @Test
    void testAnalyze() throws Exception {
        File struts = BaseTest.getResourceAsFile(this, "maven-lib/struts2-core-2.1.2.jar");
        Dependency resultStruts = new Dependency(struts);
        File axis = BaseTest.getResourceAsFile(this, "maven-lib/axis2-adb-1.4.1.jar");
        Dependency resultAxis = new Dependency(axis);
        FileNameAnalyzer instance = new FileNameAnalyzer();
        instance.analyze(resultStruts, null);
        assertTrue(resultStruts.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("struts"));

        instance.analyze(resultAxis, null);
        assertTrue(resultStruts.getEvidence(EvidenceType.VERSION).toString().toLowerCase().contains("2.1.2"));

    }

    /**
     * Test of prepare method, of class FileNameAnalyzer.
     */
    @Test
    void testInitialize() {
        FileNameAnalyzer instance = new FileNameAnalyzer();
        assertDoesNotThrow(() -> {
            instance.initialize(getSettings());
            instance.prepare(null);
        });
        assertTrue(instance.isEnabled());
    }

    /**
     * Test of close method, of class FileNameAnalyzer.
     */
    @Test
    void testClose() {
        FileNameAnalyzer instance = new FileNameAnalyzer();
        assertDoesNotThrow(instance::close);
    }
}
