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
package org.owasp.dependencycheck.dependency;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class EvidenceTest extends BaseTest {

    /**
     * Test of equals method, of class Evidence.
     */
    @Test
    void testEquals() {
        Evidence that0 = new Evidence("file", "name", "guice-3.0", Confidence.HIGHEST);
        Evidence that1 = new Evidence("jar", "package name", "dependency", Confidence.HIGHEST);
        Evidence that2 = new Evidence("jar", "package name", "google", Confidence.HIGHEST);
        Evidence that3 = new Evidence("jar", "package name", "guice", Confidence.HIGHEST);
        Evidence that4 = new Evidence("jar", "package name", "inject", Confidence.HIGHEST);
        Evidence that5 = new Evidence("jar", "package name", "inject", Confidence.LOW);
        Evidence that6 = new Evidence("jar", "package name", "internal", Confidence.LOW);
        Evidence that7 = new Evidence("manifest", "Bundle-Description", "Guice is a lightweight dependency injection framework for Java 5 and above", Confidence.MEDIUM);
        Evidence that8 = new Evidence("Manifest", "Implementation-Title", "Spring Framework", Confidence.HIGH);

        Evidence instance = new Evidence("Manifest", "Implementation-Title", "Spring Framework", Confidence.HIGH);
        assertNotEquals(instance, that0);
        assertNotEquals(instance, that1);
        assertNotEquals(instance, that2);
        assertNotEquals(instance, that3);
        assertNotEquals(instance, that4);
        assertNotEquals(instance, that5);
        assertNotEquals(instance, that6);
        assertNotEquals(instance, that7);
        assertEquals(instance, that8);
    }

    @Test
    void testHashcodeContract() {
        final Evidence titleCase = new Evidence("Manifest", "Implementation-Title", "Spring Framework", Confidence.HIGH);
        final Evidence lowerCase = new Evidence("manifest", "implementation-title", "spring framework", Confidence.HIGH);
        assertThat(titleCase, is(equalTo(lowerCase)));
        assertThat(titleCase.hashCode(), is(equalTo(lowerCase.hashCode())));
    }

    /**
     * Test of compareTo method, of class Evidence.
     */
    @Test
    void testCompareTo() {
        Evidence that0 = new Evidence("file", "name", "guice-3.0", Confidence.HIGHEST);
        Evidence that1 = new Evidence("jar", "package name", "dependency", Confidence.HIGHEST);
        Evidence that2 = new Evidence("jar", "package name", "google", Confidence.HIGHEST);
        Evidence that3 = new Evidence("jar", "package name", "guice", Confidence.HIGHEST);
        Evidence that4 = new Evidence("jar", "package name", "inject", Confidence.HIGHEST);
        Evidence that5 = new Evidence("jar", "package name", "inject", Confidence.LOW);
        Evidence that6 = new Evidence("jar", "package name", "internal", Confidence.LOW);
        Evidence that7 = new Evidence("manifest", "Bundle-Description", "Guice is a lightweight dependency injection framework for Java 5 and above", Confidence.MEDIUM);
        Evidence that8 = new Evidence("Manifest", "Implementation-Title", "Spring Framework", Confidence.HIGH);

        Evidence that9 = new Evidence("manifest", "implementation-title", "zippy", Confidence.HIGH);

        Evidence instance = new Evidence("Manifest", "Implementation-Title", "Spring Framework", Confidence.HIGH);

        int result = instance.compareTo(that0);
        assertTrue(result > 0);

        result = instance.compareTo(that1);
        assertTrue(result > 0);

        result = instance.compareTo(that2);
        assertTrue(result > 0);

        result = instance.compareTo(that3);
        assertTrue(result > 0);

        result = instance.compareTo(that4);
        assertTrue(result > 0);

        result = instance.compareTo(that5);
        assertTrue(result > 0);

        result = instance.compareTo(that6);
        assertTrue(result > 0);

        result = instance.compareTo(that7);
        assertTrue(result > 0);

        result = instance.compareTo(that8);
        assertEquals(0, result);

        result = instance.compareTo(that9);
        assertTrue(result < 0);
    }
}
