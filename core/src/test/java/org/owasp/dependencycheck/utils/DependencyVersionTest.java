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
package org.owasp.dependencycheck.utils;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;

/**
 *
 * @author Jeremy Long
 */
public class DependencyVersionTest extends BaseTest {

    /**
     * Test of parseVersion method, of class DependencyVersion.
     */
    @Test
    public void testParseVersion() {
        String version = "1.2r1";
        DependencyVersion instance = new DependencyVersion();
        instance.parseVersion(version);
        List<String> parts = instance.getVersionParts();
        assertEquals(3, parts.size());
        assertEquals("1", parts.get(0));
        assertEquals("2", parts.get(1));
        assertEquals("r1", parts.get(2));

        version = "x6.0";
        instance.parseVersion("x6.0");
        parts = instance.getVersionParts();
        assertEquals(2, parts.size());
        assertEquals("x6", parts.get(0));
        assertEquals("0", parts.get(1));
        // TODO(code review): should this be here/do something?
        //assertEquals("0", parts.get(2));


        version = "1.2.3\nThis is a test message";
        instance = new DependencyVersion();
        instance.parseVersion(version);
        parts = instance.getVersionParts();
        assertEquals(3, parts.size());
        assertEquals("1", parts.get(0));
        assertEquals("2", parts.get(1));
        assertEquals("3", parts.get(2));
    }

    /**
     * Test of iterator method, of class DependencyVersion.
     */
    @Test
    public void testIterator() {
        DependencyVersion instance = new DependencyVersion("1.2.3");
        Iterator<String> result = instance.iterator();
        assertTrue(result.hasNext());
        int count = 1;
        while (result.hasNext()) {
            String v = result.next();
            assertTrue(String.valueOf(count++).equals(v));
        }
    }

    /**
     * Test of toString method, of class DependencyVersion.
     */
    @Test
    public void testToString() {
        DependencyVersion instance = new DependencyVersion("1.2.3r1");
        String expResult = "1.2.3.r1";
        String result = instance.toString();
        assertEquals(expResult, result);
    }

    /**
     * Test of equals method, of class DependencyVersion.
     */
    @Test
    public void testEquals() {
        DependencyVersion obj = new DependencyVersion("1.2.3.r1");
        DependencyVersion instance = new DependencyVersion("1.2.3");
        boolean expResult = false;
        boolean result = instance.equals(obj);
        assertEquals(expResult, result);
        obj = new DependencyVersion("1.2.3");
        expResult = true;
        result = instance.equals(obj);
        assertEquals(expResult, result);
        
        instance = new DependencyVersion("2.0.0");
        obj = new DependencyVersion("2");
        expResult = false;
        result = instance.equals(obj);
        assertEquals(expResult, result);
        
        obj = new DependencyVersion("2.0");
        expResult = true;
        result = instance.equals(obj);
        assertEquals(expResult, result);
        
        
    }

    /**
     * Test of hashCode method, of class DependencyVersion.
     */
    @Test
    public void testHashCode() {
        DependencyVersion instance = new DependencyVersion("3.2.1");
        int expResult = 80756;
        int result = instance.hashCode();
        assertEquals(expResult, result);
    }

    /**
     * Test of matchesAtLeastThreeLevels method, of class DependencyVersion.
     */
    @Test
    public void testMatchesAtLeastThreeLevels() {

        DependencyVersion instance = new DependencyVersion("2.3.16.3");
        DependencyVersion version = new DependencyVersion("2.3.16.4");
        //true tests
        assertEquals(true, instance.matchesAtLeastThreeLevels(version));
        version = new DependencyVersion("2.3");
        assertEquals(true, instance.matchesAtLeastThreeLevels(version));
        //false tests
        version = new DependencyVersion("2.3.16.1");
        assertEquals(false, instance.matchesAtLeastThreeLevels(version));
        version = new DependencyVersion("2");
        assertEquals(false, instance.matchesAtLeastThreeLevels(version));
    }

    /**
     * Test of compareTo method, of class DependencyVersion.
     */
    @Test
    public void testCompareTo() {
        DependencyVersion instance = new DependencyVersion("1.2.3");
        DependencyVersion version = new DependencyVersion("1.2.3");
        assertEquals(0, instance.compareTo(version));
        version = new DependencyVersion("1.1");
        assertEquals(1, instance.compareTo(version));
        version = new DependencyVersion("1.2");
        assertEquals(1, instance.compareTo(version));
        version = new DependencyVersion("1.3");
        assertEquals(-1, instance.compareTo(version));
        version = new DependencyVersion("1.2.3.1");
        assertEquals(-1, instance.compareTo(version));

        instance = new DependencyVersion("1.0.1n");
        version = new DependencyVersion("1.0.1m");
        assertEquals(1, instance.compareTo(version));
        version = new DependencyVersion("1.0.1n");
        assertEquals(0, instance.compareTo(version));
        version = new DependencyVersion("1.0.1o");
        assertEquals(-1, instance.compareTo(version));

        DependencyVersion[] dv = new DependencyVersion[7];
        dv[0] = new DependencyVersion("2.1.3");
        dv[1] = new DependencyVersion("2.1.3.r2");
        dv[2] = new DependencyVersion("2.1.3.r1");
        dv[3] = new DependencyVersion("1.2.3.1");
        dv[4] = new DependencyVersion("1.2.3");
        dv[5] = new DependencyVersion("2");
        dv[6] = new DependencyVersion("-");

        DependencyVersion[] expected = new DependencyVersion[7];
        expected[0] = new DependencyVersion("-");
        expected[1] = new DependencyVersion("1.2.3");
        expected[2] = new DependencyVersion("1.2.3.1");
        expected[3] = new DependencyVersion("2");
        expected[4] = new DependencyVersion("2.1.3");
        expected[5] = new DependencyVersion("2.1.3.r1");
        expected[6] = new DependencyVersion("2.1.3.r2");
        Arrays.sort(dv);

        assertArrayEquals(expected, dv);
    }

    /**
     * Test of getVersionParts method, of class DependencyVersion.
     */
    @Test
    public void testGetVersionParts() {
        DependencyVersion instance = new DependencyVersion();
        List<String> versionParts = Arrays.asList("1", "1", "1");
        instance.setVersionParts(versionParts);
        List<String> expResult = Arrays.asList("1", "1", "1");
        List<String> result = instance.getVersionParts();
        assertEquals(expResult, result);
    }

    /**
     * Test of setVersionParts method, of class DependencyVersion.
     */
    @Test
    public void testSetVersionParts() {
        List<String> versionParts = Arrays.asList("1", "1", "1");
        DependencyVersion instance = new DependencyVersion();
        instance.setVersionParts(versionParts);
        List<String> results = instance.getVersionParts();
        assertEquals(versionParts, results);
    }
}
