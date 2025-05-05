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
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.utils.Settings;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.owasp.dependencycheck.analyzer.AnalysisPhase.FINAL;
import static org.owasp.dependencycheck.analyzer.AnalysisPhase.INITIAL;

/**
 *
 * @author Jeremy Long
 */
class AnalyzerServiceTest extends BaseDBTestCase {

    /**
     * Test of getAnalyzers method, of class AnalyzerService.
     */
    @Test
    void testGetAnalyzers() {
        AnalyzerService instance = new AnalyzerService(Thread.currentThread().getContextClassLoader(), getSettings());
        List<Analyzer> result = instance.getAnalyzers();

        boolean found = false;
        for (Analyzer a : result) {
            if ("Jar Analyzer".equals(a.getName())) {
                found = true;
                break;
            }
        }
        assertTrue(found, "JarAnalyzer loaded");
    }

    /**
     * Test of getAnalyzers method, of class AnalyzerService.
     */
    @Test
    void testGetAnalyzers_SpecificPhases() {
        AnalyzerService instance = new AnalyzerService(Thread.currentThread().getContextClassLoader(), getSettings());
        List<Analyzer> result = instance.getAnalyzers(INITIAL, FINAL);

        for (Analyzer a : result) {
            if (a.getAnalysisPhase() != INITIAL && a.getAnalysisPhase() != FINAL) {
                fail("Only expecting analyzers for phases " + INITIAL + " and " + FINAL);
            }
        }
    }

    /**
     * Test of getAnalyzers method, of class AnalyzerService.
     */
    @Test
    void testGetExperimentalAnalyzers() {
        AnalyzerService instance = new AnalyzerService(Thread.currentThread().getContextClassLoader(), getSettings());
        List<Analyzer> result = instance.getAnalyzers();
        String experimental = "CMake Analyzer";
        boolean found = false;
        boolean retiredFound = false;
        for (Analyzer a : result) {
            if (experimental.equals(a.getName())) {
                found = true;
            }
        }
        assertFalse(found, "Experimental analyzer loaded when set to false");
        assertFalse(retiredFound, "Retired analyzer loaded when set to false");

        getSettings().setBoolean(Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED, true);
        instance = new AnalyzerService(Thread.currentThread().getContextClassLoader(), getSettings());
        result = instance.getAnalyzers();
        found = false;
        retiredFound = false;
        for (Analyzer a : result) {
            if (experimental.equals(a.getName())) {
                found = true;
            }
        }
        assertTrue(found, "Experimental analyzer not loaded when set to true");
        assertFalse(retiredFound, "Retired analyzer loaded when set to false");

        getSettings().setBoolean(Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIRED_ENABLED, true);
        instance = new AnalyzerService(Thread.currentThread().getContextClassLoader(), getSettings());
        result = instance.getAnalyzers();
        found = false;
        for (Analyzer a : result) {
            if (experimental.equals(a.getName())) {
                found = true;
            }
        }
        assertFalse(found, "Experimental analyzer loaded when set to false");
    }
}
