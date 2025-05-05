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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cwe;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 *
 * @author Jeremy Long
 */
class CweDBTest extends BaseTest {

    /**
     * Test of getName method, of class CweDB.
     */
    @Test
    void testGetName() {
        String cweId = "CWE-16";
        String expResult = "Configuration";
        String result = CweDB.getName(cweId);
        assertEquals(expResult, result);

        cweId = "CWE-260000";
        result = CweDB.getName(cweId);
        assertNull(result);
    }

    /**
     * Test of getFullName method, of class CweDB.
     */
    @Test
    void testGetFullName() {
        String cweId = "CWE-16";
        String expResult = "CWE-16 Configuration";
        String result = CweDB.getFullName(cweId);
        assertEquals(expResult, result);

        cweId = "CWE-260000";
        expResult = "CWE-260000";
        result = CweDB.getFullName(cweId);
        assertEquals(expResult, result);
    }
}
