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
package org.owasp.dependencycheck.xml.hints;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Evidence;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link EvidenceMatcher}.
 *
 * @author Hans Aikema
 */
class EvidenceMatcherTest {

    private static final Evidence EVIDENCE_HIGHEST = new Evidence("source", "name", "value", Confidence.HIGHEST);
    private static final Evidence EVIDENCE_HIGH = new Evidence("source", "name", "value", Confidence.HIGH);
    private static final Evidence EVIDENCE_MEDIUM = new Evidence("source", "name", "value", Confidence.MEDIUM);
    private static final Evidence EVIDENCE_MEDIUM_SECOND_SOURCE = new Evidence("source 2", "name", "value", Confidence.MEDIUM);
    private static final Evidence EVIDENCE_LOW = new Evidence("source", "name", "value", Confidence.LOW);

    private static final Evidence REGEX_EVIDENCE_HIGHEST = new Evidence("source", "name", "value 1", Confidence.HIGHEST);
    private static final Evidence REGEX_EVIDENCE_HIGH = new Evidence("source", "name", "value 2", Confidence.HIGH);
    private static final Evidence REGEX_EVIDENCE_MEDIUM = new Evidence("source", "name", "Value will not match because of case", Confidence.MEDIUM);
    private static final Evidence REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE = new Evidence("source 2", "name", "yet another value that will match", Confidence.MEDIUM);
    private static final Evidence REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE = new Evidence("source 3", "name", "and even more values to match", Confidence.MEDIUM);
    private static final Evidence REGEX_EVIDENCE_LOW = new Evidence("source", "name", "val that should not match", Confidence.LOW);

    @Test
    void testExactMatching() {
        final EvidenceMatcher exactMatcherHighest = new EvidenceMatcher("source", "name", "value", false, Confidence.HIGHEST);
        assertTrue(exactMatcherHighest.matches(EVIDENCE_HIGHEST), "exact matcher should match EVIDENCE_HIGHEST");
        assertFalse(exactMatcherHighest.matches(EVIDENCE_HIGH), "exact matcher should not match EVIDENCE_HIGH");
        assertFalse(exactMatcherHighest.matches(EVIDENCE_MEDIUM), "exact matcher should not match EVIDENCE_MEDIUM");
        assertFalse(exactMatcherHighest.matches(EVIDENCE_MEDIUM_SECOND_SOURCE), "exact matcher should not match EVIDENCE_MEDIUM_SECOND_SOURCE");
        assertFalse(exactMatcherHighest.matches(EVIDENCE_LOW), "exact matcher should not match EVIDENCE_LOW");
    }

    @Test
    void testWildcardConfidenceMatching() {
        final EvidenceMatcher wildcardCofidenceMatcher = new EvidenceMatcher("source", "name", "value", false, null);
        assertTrue(wildcardCofidenceMatcher.matches(EVIDENCE_HIGHEST), "wildcard confidence matcher should match EVIDENCE_HIGHEST");
        assertTrue(wildcardCofidenceMatcher.matches(EVIDENCE_HIGH), "wildcard confidence matcher should match EVIDENCE_HIGH");
        assertTrue(wildcardCofidenceMatcher.matches(EVIDENCE_MEDIUM), "wildcard confidence matcher should match EVIDENCE_MEDIUM");
        assertFalse(wildcardCofidenceMatcher.matches(EVIDENCE_MEDIUM_SECOND_SOURCE), "wildcard confidence matcher should not match EVIDENCE_MEDIUM_SECOND_SOURCE");
        assertTrue(wildcardCofidenceMatcher.matches(EVIDENCE_LOW), "wildcard confidence matcher should match EVIDENCE_LOW");
    }

    @Test
    void testWildcardSourceMatching() {
        final EvidenceMatcher wildcardSourceMatcher = new EvidenceMatcher(null, "name", "value", false, Confidence.MEDIUM);
        assertFalse(wildcardSourceMatcher.matches(EVIDENCE_HIGHEST), "wildcard source matcher should not match EVIDENCE_HIGHEST");
        assertFalse(wildcardSourceMatcher.matches(EVIDENCE_HIGH), "wildcard source matcher should not match EVIDENCE_HIGH");
        assertTrue(wildcardSourceMatcher.matches(EVIDENCE_MEDIUM), "wildcard source matcher should match EVIDENCE_MEDIUM");
        assertTrue(wildcardSourceMatcher.matches(EVIDENCE_MEDIUM_SECOND_SOURCE), "wildcard source matcher should match EVIDENCE_MEDIUM_SECOND_SOURCE");
        assertFalse(wildcardSourceMatcher.matches(EVIDENCE_LOW), "wildcard source matcher should not match EVIDENCE_LOW");
    }

    @Test
    void testRegExMatching() {
        final EvidenceMatcher regexMediumMatcher = new EvidenceMatcher("source 2", "name", ".*value.*", true, Confidence.MEDIUM);
        assertFalse(regexMediumMatcher.matches(REGEX_EVIDENCE_HIGHEST), "regex medium matcher should not match REGEX_EVIDENCE_HIGHEST");
        assertFalse(regexMediumMatcher.matches(REGEX_EVIDENCE_HIGH), "regex medium matcher should not match REGEX_EVIDENCE_HIGH");
        assertFalse(regexMediumMatcher.matches(REGEX_EVIDENCE_MEDIUM), "regex medium matcher should not match REGEX_EVIDENCE_MEDIUM");
        assertTrue(regexMediumMatcher.matches(REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE), "regex medium matcher should match REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE");
        assertFalse(regexMediumMatcher.matches(REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE), "regex medium matcher should not match REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE");
        assertFalse(regexMediumMatcher.matches(REGEX_EVIDENCE_LOW), "regex medium matcher should not match REGEX_EVIDENCE_LOW");
    }

    @Test
    void testRegExWildcardSourceMatching() {
        final EvidenceMatcher regexMediumWildcardSourceMatcher = new EvidenceMatcher(null, "name", "^.*v[al]{2,2}ue[a-z ]+$", true, Confidence.MEDIUM);
        assertFalse(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_HIGHEST), "regex medium wildcard source matcher should not match REGEX_EVIDENCE_HIGHEST");
        assertFalse(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_HIGH), "regex medium wildcard source matcher should not match REGEX_EVIDENCE_HIGH");
        assertFalse(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM), "regex medium wildcard source matcher should not match REGEX_EVIDENCE_MEDIUM");
        assertTrue(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE), "regex medium wildcard source matcher should match REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE");
        assertTrue(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE), "regex medium wildcard source matcher should match REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE");
        assertFalse(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_LOW), "regex medium wildcard source matcher should not match REGEX_EVIDENCE_LOW");
    }

    @Test
    void testRegExWildcardSourceWildcardConfidenceMatching() {
        final EvidenceMatcher regexMediumWildcardSourceMatcher = new EvidenceMatcher(null, "name", ".*value.*", true, null);
        assertTrue(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_HIGHEST), "regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_HIGHEST");
        assertTrue(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_HIGH), "regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_HIGH");
        assertFalse(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM), "regex wildcard source wildcard confidence matcher should not match REGEX_EVIDENCE_MEDIUM");
        assertTrue(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE), "regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE");
        assertTrue(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE), "regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE");
        assertFalse(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_LOW), "regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_LOW");
    }

    @Test
    void testRegExWildcardSourceWildcardConfidenceFourMatching() {
        final EvidenceMatcher regexMediumWildcardSourceMatcher = new EvidenceMatcher(null, "name", "^.*[Vv][al]{2,2}[a-z ]+$", true, null);
        assertFalse(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_HIGHEST), "regex wildcard source wildcard confidence matcher should not match REGEX_EVIDENCE_HIGHEST");
        assertFalse(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_HIGH), "regex wildcard source wildcard confidence matcher should not match REGEX_EVIDENCE_HIGH");
        assertTrue(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM), "regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_MEDIUM");
        assertTrue(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE), "regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE");
        assertTrue(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE), "regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE");
        assertTrue(regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_LOW), "regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_LOW");
    }
}
