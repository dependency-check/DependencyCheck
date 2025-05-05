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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.utils.Settings;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 * @author jeremy long
 */
class NpmCPEAnalyzerTest extends BaseDBTestCase {

    /**
     * Test of getName method, of class CPEAnalyzer.
     */
    @Test
    void testGetName() {
        NpmCPEAnalyzer instance = new NpmCPEAnalyzer();
        String expResult = "NPM CPE Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method, of class CPEAnalyzer.
     */
    @Test
    void testGetAnalyzerEnabledSettingKey() {
        NpmCPEAnalyzer instance = new NpmCPEAnalyzer();
        String expResult = Settings.KEYS.ANALYZER_NPM_CPE_ENABLED;
        String result = instance.getAnalyzerEnabledSettingKey();
        assertEquals(expResult, result);
    }
}
