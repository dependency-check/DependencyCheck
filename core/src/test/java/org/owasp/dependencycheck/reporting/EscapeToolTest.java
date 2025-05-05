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
package org.owasp.dependencycheck.reporting;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class EscapeToolTest {

    /**
     * Test of url method, of class EscapeTool.
     */
    @Test
    void testUrl() {
        String text = null;
        EscapeTool instance = new EscapeTool();
        String expResult = null;
        String result = instance.url(text);
        assertEquals(expResult, result);

        text = "";
        expResult = "";
        result = instance.url(text);
        assertEquals(expResult, result);

        text = " ";
        expResult = "+";
        result = instance.url(text);
        assertEquals(expResult, result);
    }

    /**
     * Test of html method, of class EscapeTool.
     */
    @Test
    void testHtml() {
        EscapeTool instance = new EscapeTool();
        String text = null;
        String expResult = null;
        String result = instance.html(text);
        assertEquals(expResult, result);

        text = "";
        expResult = "";
        result = instance.html(text);
        assertEquals(expResult, result);

        text = "<div>";
        expResult = "&lt;div&gt;";
        result = instance.html(text);
        assertEquals(expResult, result);
    }

    /**
     * Test of xml method, of class EscapeTool.
     */
    @Test
    void testXml() {
        EscapeTool instance = new EscapeTool();
        String text = null;
        String expResult = null;
        String result = instance.xml(text);
        assertEquals(expResult, result);

        text = "";
        expResult = "";
        result = instance.xml(text);
        assertEquals(expResult, result);

        text = "<div>";
        expResult = "&lt;div&gt;";
        result = instance.xml(text);
        assertEquals(expResult, result);
    }

    /**
     * Test of json method, of class EscapeTool.
     */
    @Test
    void testJson() {
        String text = null;
        EscapeTool instance = new EscapeTool();
        String expResult = null;
        String result = instance.json(text);
        assertEquals(expResult, result);

        text = "";
        expResult = "";
        result = instance.json(text);
        assertEquals(expResult, result);

        text = "test \"quote\"\"";
        expResult = "test \\\"quote\\\"\\\"";
        result = instance.json(text);
        assertEquals(expResult, result);
    }

    /**
     * Test of csv method, of class EscapeTool.
     */
    @Test
    void testCsv() {
        String text = null;
        EscapeTool instance = new EscapeTool();
        String expResult = "\"\"";
        String result = instance.csv(text);
        assertEquals(expResult, result);

        text = "";
        expResult = "\"\"";
        result = instance.csv(text);
        assertEquals(expResult, result);

        text = "one, two";
        expResult = "\"one, two\"";
        result = instance.csv(text);
        assertEquals(expResult, result);
    }

    /**
     * Test of csvIdentifiers method, of class EscapeTool.
     */
    @Test
    void testCsvIdentifiers() {
        EscapeTool instance = new EscapeTool();
        Set<Identifier> ids = null;
        String expResult = "\"\"";
        String result = instance.csvIdentifiers(ids);
        assertEquals(expResult, result);

        ids = new HashSet<>();
        expResult = "\"\"";
        result = instance.csvIdentifiers(ids);
        assertEquals(expResult, result);

        ids = new HashSet<>();
        ids.add(new GenericIdentifier("somegroup:something:1.0", Confidence.HIGH));
        expResult = "somegroup:something:1.0";
        result = instance.csvIdentifiers(ids);
        assertEquals(expResult, result);

        ids = new HashSet<>();
        ids.add(new GenericIdentifier("somegroup:something:1.0", Confidence.HIGH));
        ids.add(new GenericIdentifier("somegroup2:something:1.2", Confidence.HIGH));
        expResult = "\"somegroup:something:1.0, somegroup2:something:1.2\"";
        String expResult2 = "\"somegroup2:something:1.2, somegroup:something:1.0\"";
        result = instance.csvIdentifiers(ids);
        assertTrue(expResult.equals(result) || expResult2.equals(result));
    }

    /**
     * Test of csvCpeConfidence method, of class EscapeTool.
     */
    @Test
    void testCsvCpeConfidence() {
        EscapeTool instance = new EscapeTool();
        Set<Identifier> ids = null;
        String expResult = "\"\"";
        String result = instance.csvCpeConfidence(ids);
        assertEquals(expResult, result);

        ids = new HashSet<>();
        expResult = "\"\"";
        result = instance.csvCpeConfidence(ids);
        assertEquals(expResult, result);

        ids = new HashSet<>();
        GenericIdentifier i1 = new GenericIdentifier("cpe:/a:somegroup:something:1.0", Confidence.HIGH);
        ids.add(i1);
        expResult = "HIGH";
        result = instance.csvCpeConfidence(ids);
        assertEquals(expResult, result);

        ids = new HashSet<>();
        i1 = new GenericIdentifier("cpe:/a:somegroup:something:1.0", Confidence.HIGH);
        ids.add(i1);
        GenericIdentifier i2 = new GenericIdentifier("cpe:/a:somegroup:something2:1.0", Confidence.MEDIUM);
        ids.add(i2);

        expResult = "\"HIGH, MEDIUM\"";
        String expResult2 = "\"MEDIUM, HIGH\"";
        result = instance.csvCpeConfidence(ids);
        assertTrue(expResult.equals(result) || expResult2.equals(result));
    }
}
