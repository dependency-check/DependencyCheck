/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.utils;

import org.junit.jupiter.api.Test;
import org.semver4j.Semver;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class SemverTest {

    /**
     * Test of semver4j. See https://github.com/dependency-check/DependencyCheck/issues/5128#issuecomment-1343080426
     */
    @Test
    void testSemver() {
        Semver semver = new Semver("3.1.4");
        assertTrue(semver.satisfies("^3.0.0-0"));
    }

    /**
     * Test of semver4j. See https://github.com/dependency-check/DependencyCheck/issues/5158
     */
    @Test
    void testSemverComplex() {
        Semver semver = new Semver("18.11.5");
        assertFalse(semver.satisfies("^14.14.20 || ^16.0.0"));

        semver = new Semver("14.15.0");
        assertTrue(semver.satisfies("^14.14.20 || ^16.0.0"));
    }
}
