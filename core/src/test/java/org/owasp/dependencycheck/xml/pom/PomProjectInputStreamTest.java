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
package org.owasp.dependencycheck.xml.pom;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 * @author Jeremy Long
 */
class PomProjectInputStreamTest {

    private final String POM = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n"
            + "<!DOCTYPE xml [<!ENTITY quot \"&#34;\">\n"
            + "               <!ENTITY euro \"&#x20ac;\">\n"
            + "               <!ENTITY reg \"&#174;\">\n"
            + "               <!ENTITY nbsp \"&#160;\">\n"
            + "               <!ENTITY Auml \"&#196;\">\n"
            + "               <!ENTITY Uuml \"&#220;\">\n"
            + "               <!ENTITY Ouml \"&#214;\">\n"
            + "               <!ENTITY auml \"&#228;\">\n"
            + "               <!ENTITY uuml \"&#252;\">\n"
            + "               <!ENTITY ouml \"&#246;\">\n"
            + "               <!ENTITY raquo \"&#187;\">\n"
            + "               <!ENTITY szlig \"&#223;\">]>\n"
            + "<project></project>";

    private final String INVALID = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n"
            + "<!DOCTYPE xml [<!ENTITY quot \"&#34;\">\n"
            + "               <!ENTITY euro \"&#x20ac;\">\n"
            + "               <!ENTITY reg \"&#174;\">\n"
            + "               <!ENTITY nbsp \"&#160;\">\n"
            + "               <!ENTITY Auml \"&#196;\">\n"
            + "               <!ENTITY Uuml \"&#220;\">\n"
            + "               <!ENTITY Ouml \"&#214;\">\n"
            + "               <!ENTITY auml \"&#228;\">\n"
            + "               <!ENTITY uuml \"&#252;\">\n"
            + "               <!ENTITY ouml \"&#246;\">\n"
            + "               <!ENTITY raquo \"&#187;\">\n"
            + "               <!ENTITY szlig \"&#223;\">]>\n"
            + "<blue></blue>";

    @Test
    void testFilter() throws IOException {
        InputStream in = new ByteArrayInputStream(POM.getBytes(StandardCharsets.UTF_8));
        PomProjectInputStream instance = new PomProjectInputStream(in);
        byte[] expected = "<project></project>".getBytes(StandardCharsets.UTF_8);
        byte[] results = new byte[expected.length];
        int count = instance.read(results, 0, results.length);
        assertEquals(results.length, count);
        assertArrayEquals(expected, results);
        instance.close();

        in = new ByteArrayInputStream(INVALID.getBytes(StandardCharsets.UTF_8));
        instance = new PomProjectInputStream(in);
        results = new byte[100];
        count = instance.read(results, 0, 100);
        assertEquals(-1, count);
        instance.close();

    }

    /**
     * Test of findSequence method, of class PomProjectInputStream.
     */
    @Test
    void testFindSequence() {

        byte[] sequence = "project".getBytes(StandardCharsets.UTF_8);
        byte[] buffer = "my big project".getBytes(StandardCharsets.UTF_8);

        int expResult = 7;
        int result = PomProjectInputStream.findSequence(sequence, buffer);
        assertEquals(expResult, result);

        sequence = "<project".getBytes(StandardCharsets.UTF_8);
        buffer = "my big project".getBytes(StandardCharsets.UTF_8);

        expResult = -1;
        result = PomProjectInputStream.findSequence(sequence, buffer);
        assertEquals(expResult, result);

        sequence = "bigger sequence".getBytes(StandardCharsets.UTF_8);
        buffer = "buffer".getBytes(StandardCharsets.UTF_8);

        expResult = -1;
        result = PomProjectInputStream.findSequence(sequence, buffer);
        assertEquals(expResult, result);

        sequence = "fff".getBytes(StandardCharsets.UTF_8);
        buffer = "buffer".getBytes(StandardCharsets.UTF_8);

        expResult = -1;
        result = PomProjectInputStream.findSequence(sequence, buffer);
        assertEquals(expResult, result);
    }
}
