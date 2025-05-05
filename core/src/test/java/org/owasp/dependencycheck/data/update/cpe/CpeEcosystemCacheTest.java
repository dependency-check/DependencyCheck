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
package org.owasp.dependencycheck.data.update.cpe;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.utils.Pair;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class CpeEcosystemCacheTest {

    /**
     * Test of getEcosystem method, of class CpeEcosystemCache.
     */
    @Test
    void testGetEcosystem() {
        Pair<String, String> key = new Pair<>("apache", "zookeeper");
        Map<Pair<String, String>, String> map = new HashMap<>();
        map.put(key, "java");
        CpeEcosystemCache.setCache(map);

        String expected = "java";
        String result = CpeEcosystemCache.getEcosystem("apache", "zookeeper", null);
        assertEquals(expected, result);

        //changes to MULTIPLE = which is returned as null
        result = CpeEcosystemCache.getEcosystem("apache", "zookeeper", "c++");
        assertNull(result);

        result = CpeEcosystemCache.getEcosystem("pivotal", "spring-framework", null);
        assertNull(result);

        expected = "java";
        result = CpeEcosystemCache.getEcosystem("pivotal", "spring-framework", "java");
        assertEquals(expected, result);

        expected = "java";
        result = CpeEcosystemCache.getEcosystem("pivotal", "spring-framework", "java");
        assertEquals(expected, result);

        result = CpeEcosystemCache.getEcosystem("microsoft", "word", null );
        assertNull(result);

        result = CpeEcosystemCache.getEcosystem("microsoft", "word", null );
        assertNull(result);

        result = CpeEcosystemCache.getEcosystem("microsoft", "word", "" );
        assertNull(result);
    }

    /**
     * Test of setCache method, of class CpeEcosystemCache.
     */
    @Test
    void testSetCache() {
        Map<Pair<String, String>, String> map = new HashMap<>();
        CpeEcosystemCache.setCache(map);
        assertTrue(CpeEcosystemCache.isEmpty());

        map = new HashMap<>();
        Pair<String, String> key = new Pair<>("apache", "zookeeper");
        map.put(key, "java");
        CpeEcosystemCache.setCache(map);

        assertFalse(CpeEcosystemCache.isEmpty());
    }

    /**
     * Test of getChanged method, of class CpeEcosystemCache.
     */
    @Test
    void testGetChanged() {
        Pair<String, String> key = new Pair<>("apache", "zookeeper");
        Map<Pair<String, String>, String> map = new HashMap<>();
        map.put(key, "java");
        CpeEcosystemCache.setCache(map);

        Map<Pair<String, String>, String> result = CpeEcosystemCache.getChanged();
        assertTrue(result.isEmpty());

        CpeEcosystemCache.getEcosystem("apache", "zookeeper", "java");
        result = CpeEcosystemCache.getChanged();
        assertTrue(result.isEmpty());

        CpeEcosystemCache.getEcosystem("apache", "zookeeper", null);
        result = CpeEcosystemCache.getChanged();
        assertTrue(result.isEmpty());

        //zookeeper is already at multiple- no change
        CpeEcosystemCache.getEcosystem("apache", "zookeeper", "c++");
        result = CpeEcosystemCache.getChanged();
        assertFalse(result.isEmpty());
    }

    /**
     * Test of isEmpty method, of class CpeEcosystemCache.
     */
    @Test
    void testIsEmpty() {
        Map<Pair<String, String>, String> map = new HashMap<>();
        CpeEcosystemCache.setCache(map);
        boolean expResult = true;
        boolean result = CpeEcosystemCache.isEmpty();
        assertEquals(expResult, result);
        map.put(new Pair<>("apache", "zookeeper"), "MULTPILE");
        expResult = false;
        result = CpeEcosystemCache.isEmpty();
        assertEquals(expResult, result);
    }

}
