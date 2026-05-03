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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.suppression;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import java.io.File;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test of the suppression parser.
 *
 * @author Jeremy Long
 */
class SuppressionParserTest extends BaseTest {

    /**
     * Test of parseSuppressionRules method, of class SuppressionParser for the
     * v1.0 suppression XML Schema.
     */
    @Test
    void testParseSuppressionRulesV1dot0() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "suppressions.xml");
        SuppressionParser instance = new SuppressionParser();
        List<SuppressionRule> result = instance.parseSuppressionRules(file);
        assertEquals(5, result.size());
    }

    /**
     * Test of parseSuppressionRules method, of class SuppressionParser for the
     * v1.1 suppression XML Schema.
     */
    @Test
    void testParseSuppressionRulesV1dot1() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "suppressions_1_1.xml");
        SuppressionParser instance = new SuppressionParser();
        List<SuppressionRule> result = instance.parseSuppressionRules(file);
        assertEquals(5, result.size());
    }

    /**
     * Test of parseSuppressionRules method, of class SuppressionParser for the
     * v1.2 suppression XML Schema.
     */
    @Test
    void testParseSuppressionRulesV1dot2() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "suppressions_1_2.xml");
        SuppressionParser instance = new SuppressionParser();
        List<SuppressionRule> result = instance.parseSuppressionRules(file);
        assertEquals(4, result.size());
    }

    /**
     * Test of parseSuppressionRules method, of class SuppressionParser for the
     * v1.2 suppression XML Schema.
     */
    @Test
    void testParseSuppressionRulesV1dot3() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "suppressions_1_3.xml");
        SuppressionParser instance = new SuppressionParser();
        List<SuppressionRule> result = instance.parseSuppressionRules(file);
        assertEquals(4, result.size());
    }

    /**
     * Test of parseSuppressionRules method, of class SuppressionParser for the
     * v1.4 suppression XML Schema.
     */
    @Test
    void testParseSuppressionRulesV1dot4() throws SuppressionParseException {
        File file = BaseTest.getResourceAsFile(this, "suppressions_1_4.xml");
        SuppressionParser instance = new SuppressionParser();
        List<SuppressionRule> suppressionRules = instance.parseSuppressionRules(file);

        assertEquals(7, suppressionRules.size());
    }

    /**
     * Any content that follows Schema 1.3 is also valid content according to Schema 1.4
     */
    @Test
    void testParseSuppressionRulesV1dot4BackwardsCompability() throws SuppressionParseException {
        // 'suppressions_1_4_no_groups.xml' has the same content as 'suppressions_1_3.xml'. But follows schema 1.4
        File file = BaseTest.getResourceAsFile(this, "suppressions_1_4_no_groups.xml");
        SuppressionParser instance = new SuppressionParser();
        List<SuppressionRule> suppressionRules = instance.parseSuppressionRules(file);

        assertEquals(4, suppressionRules.size());
    }

    /**
     * If a suppression is present in a group and does not have attributes set, then the ones from the group are used
     * as defaults.
     */
    @Test
    void testParseSuppressionV1dot4Inherits() throws SuppressionParseException {
        File file = BaseTest.getResourceAsFile(this, "suppressions_1_4.xml");
        SuppressionParser instance = new SuppressionParser();
        List<SuppressionRule> suppressionRules = instance.parseSuppressionRules(file);

        // CVE-2013-1338 in test xml has no attributes and should inherit the ones set on group level.
        List<SuppressionRule> filteredSuppressions = suppressionRules.stream().
                filter(s -> s.getCve().contains("CVE-2013-1338"))
                .collect(Collectors.toList());
        assertEquals(1, filteredSuppressions.size());
        SuppressionRule rule = filteredSuppressions.get(0);

        Instant expectedTime = LocalDate.of(2046, 1, 1)
                .atStartOfDay(ZoneOffset.UTC)
                .toInstant();
        assertEquals(expectedTime, rule.getUntil().toInstant());
        assertTrue(rule.isBase());
    }

    /**
     * If a suppression in a suppression group has attributes set, then those override those of the suppressionGroup.
     */
    @Test
    void testParseSuppressionV1dot4AttributeOverrides() throws SuppressionParseException {
        File file = BaseTest.getResourceAsFile(this, "suppressions_1_4.xml");
        SuppressionParser instance = new SuppressionParser();
        List<SuppressionRule> suppressionRules = instance.parseSuppressionRules(file);

        // CVE-2013-1339 in test xml has attribute {code (until="2027-01-01Z")} set and is present in  suppressionGroup.
        List<SuppressionRule> filteredSuppressions = suppressionRules.stream().
                filter(s -> s.getCve().contains("CVE-2013-1339"))
                .collect(Collectors.toList());
        assertEquals(1, filteredSuppressions.size());
        SuppressionRule rule = filteredSuppressions.get(0);

        Instant expectedTime = LocalDate.of(2027, 1, 1)
                .atStartOfDay(ZoneOffset.UTC)
                .toInstant();
        assertEquals(expectedTime, rule.getUntil().toInstant());
        assertFalse(rule.isBase());
    }

}
