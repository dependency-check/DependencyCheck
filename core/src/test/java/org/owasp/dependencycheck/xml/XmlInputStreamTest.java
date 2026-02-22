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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class XmlInputStreamTest {

    /**
     * Test of length method, of class XmlInputStream.
     */
    @Test
    void testLength() {
        String data = "";
        InputStream stream = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        XmlInputStream instance = new XmlInputStream(stream);
        int expResult = 0;
        int result = instance.length();
        assertEquals(expResult, result);

        data = "Input data";
        stream = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        instance = new XmlInputStream(stream);
        result = instance.length();
        assertTrue(result > 0);
    }

    /**
     * Test of read method, of class XmlInputStream.
     */
    @Test
    void testRead_0args() throws Exception {
        String data = "";
        InputStream stream = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        XmlInputStream instance = new XmlInputStream(stream);
        int expResult = -1;
        int result = instance.read();
        assertEquals(expResult, result);

        data = "*";
        stream = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        instance = new XmlInputStream(stream);
        expResult = 42;
        result = instance.read();
        assertEquals(expResult, result);
    }

    /**
     * Test of read method, of class XmlInputStream.
     */
    @Test
    void testRead_3args() throws Exception {
        byte[] data = new byte[10];
        int offset = 0;
        int length = 10;
        byte[] expected = "abcdefghij".getBytes(StandardCharsets.UTF_8);
        String text = "abcdefghijklmnopqrstuvwxyz";
        InputStream stream = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
        XmlInputStream instance = new XmlInputStream(stream);
        int expResult = 10;
        int result = instance.read(data, offset, length);
        assertEquals(expResult, result);
        assertArrayEquals(expected, data);


        data = new byte[5];
        offset = 0;
        length = 5;
        expected = "&#38;".getBytes(StandardCharsets.UTF_8);
        text = "&amp;";
        stream = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
        instance = new XmlInputStream(stream);
        expResult = 5;
        result = instance.read(data, offset, length);
        assertEquals(expResult, result);
        assertArrayEquals(expected, data);

        data = new byte[10];
        offset = 0;
        length = 10;
        expected = "&#38; test".getBytes(StandardCharsets.UTF_8);
        text = "& test";
        stream = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
        instance = new XmlInputStream(stream);
        expResult = 10;
        result = instance.read(data, offset, length);
        assertEquals(expResult, result);
        assertArrayEquals(expected, data);
    }

    /**
     * Test of toString method, of class XmlInputStream.
     */
    @Test
    void testToString() throws IOException {
        String data = "test";
        InputStream stream = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        XmlInputStream instance = new XmlInputStream(stream);
        int r = instance.read();
        assertEquals('t', r);
        String expResult = "[1]-\"t\" ( 74)";
        String result = instance.toString();
        assertEquals(expResult, result);
        r = instance.read();
        assertEquals('e', r);
        expResult = "[2]-\"te\" ( 74 65)";
        result = instance.toString();
        assertEquals(expResult, result);

    }
}
