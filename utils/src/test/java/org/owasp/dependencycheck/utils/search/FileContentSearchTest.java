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
package org.owasp.dependencycheck.utils.search;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.utils.BaseTest;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 * @author Jeremy Long
 */
class FileContentSearchTest extends BaseTest {

    /**
     * Test of contains method, of class FileContentSearch.
     */
    @Test
    void testContains_File_String() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "SearchTest.txt");
        String pattern = "blue";
        boolean expResult = false;
        boolean result = FileContentSearch.contains(file, pattern);
        assertEquals(expResult, result);

        pattern = "test";
        expResult = false;
        result = FileContentSearch.contains(file, pattern);
        assertEquals(expResult, result);


        pattern = "(?i)test";
        expResult = true;
        result = FileContentSearch.contains(file, pattern);
        assertEquals(expResult, result);
    }

    /**
     * Test of contains method, of class FileContentSearch.
     */
    @Test
    void testContains_File_List() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "SearchTest.txt");
        String[] patterns = {"jeremy long", "blue"};

        boolean expResult = false;
        boolean result = FileContentSearch.contains(file, patterns);
        assertEquals(expResult, result);

        String[] patterns2 = {"jeremy long", "blue", "(?i)jeremy long"};
        expResult = true;
        result = FileContentSearch.contains(file, patterns2);
        assertEquals(expResult, result);
    }

}
