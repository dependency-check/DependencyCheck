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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.dependency;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author jeremy
 */
class CweSetTest {

    /**
     * Test of getEntries method, of class CweSet.
     */
    @Test
    void testGetEntries() {
        CweSet instance = new CweSet();
        Set<String> result = instance.getEntries();
        assertTrue(result.isEmpty());
    }

    /**
     * Test of addCwe method, of class CweSet.
     */
    @Test
    void testAddCwe() {
        System.out.println("addCwe");
        String cwe = "CWE-89";
        CweSet instance = new CweSet();
        instance.addCwe(cwe);
        assertFalse(instance.getEntries().isEmpty());
    }

    /**
     * Test of toString method, of class CweSet.
     */
    @Test
    void testToString() {
        CweSet instance = new CweSet();
        instance.addCwe("CWE-79");
        String expResult = "CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')";
        String result = instance.toString();
        assertEquals(expResult, result);
    }

    /**
     * Test of stream method, of class CweSet.
     */
    @Test
    void testStream() {
        CweSet instance = new CweSet();
        instance.addCwe("79");
        String expResult = "79";
        String result = instance.stream().collect(Collectors.joining(" "));
        assertEquals(expResult, result);
    }

    /**
     * Test of getFullCwes method, of class CweSet.
     */
    @Test
    void testGetFullCwes() {
        CweSet instance = new CweSet();
        instance.addCwe("CWE-89");
        instance.addCwe("CWE-79");
        Map<String, String> expResult = new HashMap<>();
        expResult.put("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')");
        expResult.put("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')");
        Map<String, String> result = instance.getFullCwes();
        for (Map.Entry<String,String> entry : expResult.entrySet()) {
            assertEquals(result.get(entry.getKey()), entry.getValue());
        }
    }

}
