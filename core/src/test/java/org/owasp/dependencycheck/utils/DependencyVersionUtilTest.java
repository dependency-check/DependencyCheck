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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.owasp.dependencycheck.BaseTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 *
 * @author Jeremy Long
 */
class DependencyVersionUtilTest extends BaseTest {

    @ParameterizedTest
    @CsvSource({
        "1.3.0-alpha10, 1.3.0.alpha10",
        "1.3.0-alpha11, 1.3.0.alpha11",
        "logback-classic-1.3.0-alpha10.jar, 1.3.0.alpha10",
        "library-1.3.0-ALPHA10.jar, 1.3.0.alpha10",
        "library-1.3.0-alpha-10.jar, 1.3.0.alpha-10",
        "library-1.3.0-alpha_10.jar, 1.3.0.alpha_10",
        "library-1.3.0-beta2.jar, 1.3.0.beta2",
        "library-1.3.0-beta-2.jar, 1.3.0.beta-2",
        "library-1.3.0-beta_2.jar, 1.3.0.beta_2",
        "library-3-alpha10.jar, 3.alpha10",
        "library-3-beta2.jar, 3.beta2"
    })
    void testExtractNumberedPrereleaseQualifiers(String input, String expected) {
        final DependencyVersion version = DependencyVersionUtil.parseVersion(input);
        assertNotNull(version);
        assertEquals(expected, version.toString());
    }

    @ParameterizedTest
    @CsvSource({
        "library-1.3.0-alpha.jar, 1.3.0.alpha",
        "library-1.3.0-beta.jar, 1.3.0.beta",
        "library-3-alpha.jar, 3.alpha",
        "library-3-beta.jar, 3.beta",
        "library-1.3.0-RC1.jar, 1.3.0.rc1",
        "library-1.3.0-SNAPSHOT.jar, 1.3.0.snapshot"
    })
    void testExtractOtherQualifiersIsUnchanged(String input, String expected) {
        final DependencyVersion version = DependencyVersionUtil.parseVersion(input);
        assertNotNull(version);
        assertEquals(expected, version.toString());
    }

    @Test
    void testNumberedPrereleaseDoesNotConsumeAnotherVersion() {
        final String input = "library-1.3.0-alpha10-other-2.0.jar";
        assertNull(DependencyVersionUtil.parseVersion(input));
        assertEquals("1.3.0.alpha10", DependencyVersionUtil.parseVersion(input, true).toString());
        assertNull(DependencyVersionUtil.parseVersion("library-3-alpha10-other-4.jar"));
    }

    /**
     * Test of parseVersion method, of class DependencyVersionUtil.
     */
    @Test
    void testParseVersion_String() {
        final String[] fileName = {"openssl1.0.1c", "something-0.9.5.jar", "lib2-1.1.jar", "lib1.5r4-someflag-R26.jar",
            "lib-1.2.5-dev-20050313.jar", "testlib_V4.4.0.jar", "lib-core-2.0.0-RC1-SNAPSHOT.jar",
            "lib-jsp-2.0.1_R114940.jar", "dev-api-2.3.11_R121413.jar", "lib-api-3.7-SNAPSHOT.jar",
            "-", "", "1.3-beta", "6", "jsf-impl-2.2.8-02.jar",
            "plone.rfc822-1.1.1-py2-none-any.whl"};
        final String[] expResult = {"1.0.1c", "0.9.5", "1.1", "1.5.r4", "1.2.5.dev-20050313", "4.4.0", "2.0.0.rc1",
            "2.0.1.r114940", "2.3.11.r121413", "3.7.snapshot", "-", null, "1.3.beta", "6",
            "2.2.8.02", "1.1.1"};

        for (int i = 0; i < fileName.length; i++) {
            final DependencyVersion version = DependencyVersionUtil.parseVersion(fileName[i]);
            String result = null;
            if (version != null) {
                result = version.toString();
            }
            assertEquals(expResult[i], result, "Failed extraction on \"" + fileName[i] + "\".");
        }

        String[] failingNames = {"no-version-identified.jar", "somelib-04aug2000r7-dev.jar", /*"no.version15.jar",*/
            "lib_1.0_spec-1.1.jar", "lib-api_1.0_spec-1.0.1.jar"};
        for (String failingName : failingNames) {
            final DependencyVersion version = DependencyVersionUtil.parseVersion(failingName);
            assertNull(version, "Found version in name that should have failed \"" + failingName + "\".");
        }
    }

    /**
     * Test of parseVersion method, of class DependencyVersionUtil, for versions
     * that consist of a number directly followed by a single letter and no
     * period - the scheme used by libjpeg (8a, 9d, 9e).
     *
     * See https://github.com/dependency-check/DependencyCheck/issues/4139
     */
    @Test
    void testParseVersion_singleLetterSuffixWithoutPeriod() {
        final String[] names = {"9e", "9d", "8a", "libjpeg-9e", "jpegsr9e"};
        final String[] expected = {"9e", "9d", "8a", "9e", "9e"};

        for (int i = 0; i < names.length; i++) {
            final DependencyVersion version = DependencyVersionUtil.parseVersion(names[i]);
            String result = null;
            if (version != null) {
                result = version.toString();
            }
            assertEquals(expected[i], result, "Failed extraction on \"" + names[i] + "\".");
        }
    }

    /**
     * The user visible consequence of dropping the suffix: 8a and 8b both collapse onto "8", so
     * the version CPEAnalyzer derives from the evidence compares equal to the version of a CPE
     * for a different release. Its exact match is
     * {@code parseVersion(evidence).equals(parseVersion(cpe.getVersion()))}, so a dependency at
     * 8a matched the CPE of 8b, and the identified version printed in the report was "8".
     */
    @Test
    void testParseVersion_singleLetterReleasesAreNotConflated() {
        final DependencyVersion evidence = DependencyVersionUtil.parseVersion("libjpeg-turbo-8a.tar.gz", true);

        assertEquals("8a", evidence.toString());
        assertEquals(DependencyVersionUtil.parseVersion("8a"), evidence);
        assertNotEquals(DependencyVersionUtil.parseVersion("8b"), evidence);
        assertNotEquals(DependencyVersionUtil.parseVersion("9e"), DependencyVersionUtil.parseVersion("9d"));
    }

    /**
     * Test of parseVersion method, of class DependencyVersionUtil.
     */
    @Test
    void testParseVersion_String_boolean() {
        //cpe:/a:playframework:play_framework:2.1.1:rc1-2.9.x-backport
        String text = "2.1.1.rc1.2.9.x-backport";
        boolean firstMatchOnly = false;
        DependencyVersion expResult;
        DependencyVersion result = DependencyVersionUtil.parseVersion(text, firstMatchOnly);
        assertNull(result);
        firstMatchOnly = true;
        expResult = DependencyVersionUtil.parseVersion("2.1.1.rc1");
        result = DependencyVersionUtil.parseVersion(text, firstMatchOnly);
        assertEquals(expResult, result);

        result = DependencyVersionUtil.parseVersion("1.0.0-RC", firstMatchOnly);
        assertEquals(4, result.getVersionParts().size());
        assertEquals("rc", result.getVersionParts().get(3));

        result = DependencyVersionUtil.parseVersion("1.0.0-RC2", firstMatchOnly);
        assertEquals(4, result.getVersionParts().size());
        assertEquals("rc2", result.getVersionParts().get(3));
    }

    /**
     * Test of parsePreVersion method, of class DependencyVersionUtil.
     */
    @Test
    void testParsePreVersion() {
        String text = "library-name-1.4.1r2-release.jar";
        String expResult = "library-name";
        String result = DependencyVersionUtil.parsePreVersion(text);
        assertEquals(expResult, result);

    }
}
