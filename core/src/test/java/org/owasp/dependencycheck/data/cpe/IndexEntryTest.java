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
package org.owasp.dependencycheck.data.cpe;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 * @author Jeremy Long
 */
class IndexEntryTest extends BaseTest {

    /**
     * Test of setName method, of class IndexEntry.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    void testSetName() throws Exception {
        String name = "cpe:/a:apache:struts:1.1:rc2";

        IndexEntry instance = new IndexEntry();
        instance.parseName(name);

        assertEquals("apache", instance.getVendor());
        assertEquals("struts", instance.getProduct());
    }
}
