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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 * @author Jeremy Long
 */
class XmlEntityTest {

    /**
     * Test of fromNamedReference method, of class XmlEntity.
     */
    @Test
    void testFromNamedReference() {
        CharSequence s = null;
        String expResult = null;
        String result = XmlEntity.fromNamedReference(s);
        assertEquals(expResult, result);

        s = "somethingWrong";
        expResult = null;
        result = XmlEntity.fromNamedReference(s);
        assertEquals(expResult, result);

        s = "amp";
        expResult = "&#38;";
        result = XmlEntity.fromNamedReference(s);
        assertEquals(expResult, result);
        
        s = "acute";
        expResult = "&#180;";
        result = XmlEntity.fromNamedReference(s);
        assertEquals(expResult, result);
    }

}
