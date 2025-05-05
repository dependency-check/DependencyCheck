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

import java.util.ArrayList;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 * @author jeremy long
 */
class AbstractNpmAnalyzerIT {

    /**
     * Test of determineVersionFromMap method, of class AbstractNpmAnalyzer.
     */
    @Test
    void testDetermineVersionFromMap() {
        String versionRange = ">2.1.1 <5.0.1";
        Collection<String> availableVersions = new ArrayList<>();
        availableVersions.add("2.0.2");
        availableVersions.add("5.0.2");
        availableVersions.add("10.1.0");
        availableVersions.add("8.1.0");
        availableVersions.add("5.1.0");
        availableVersions.add("7.1.0");
        availableVersions.add("3.0.0");
        availableVersions.add("2.0.0");
        String expResult = "3.0.0";
        String result = AbstractNpmAnalyzer.determineVersionFromMap(versionRange, availableVersions);
        assertEquals(expResult, result);
    }

    @Test
    void testDetermineVersionFromMap_1() {
        String versionRange = ">2.1.1 <5.0.1";
        Collection<String> availableVersions = new ArrayList<>();
        availableVersions.add("10.1.0");
        String expResult = "10.1.0";
        String result = AbstractNpmAnalyzer.determineVersionFromMap(versionRange, availableVersions);
        assertEquals(expResult, result);
    }

    @Test
    void testDetermineVersionFromMap_2() {
        String versionRange = ">2.1.1 <5.0.1";
        Collection<String> availableVersions = new ArrayList<>();
        availableVersions.add("2.0.2");
        availableVersions.add("5.0.2");
        String expResult = "2.0.2";
        String result = AbstractNpmAnalyzer.determineVersionFromMap(versionRange, availableVersions);
        assertEquals(expResult, result);
    }
}
