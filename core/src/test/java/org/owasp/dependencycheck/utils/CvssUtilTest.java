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
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV2;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2Data;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3Data;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 *
 * @author Jeremy Long
 */
class CvssUtilTest {

    /**
     * Test of vectorToCvssV2 method, of class CvssUtil.
     */
    @Test
    void testVectorToCvssV2() {
        String vectorString = "/AV:L/AC:L/Au:N/C:N/I:N/A:C";
        Double baseScore = 1.0;
        CvssV2 result = CvssUtil.vectorToCvssV2(vectorString, baseScore);
        assertEquals(CvssV2Data.Version._2_0, result.getCvssData().getVersion());
        assertEquals(CvssV2Data.AccessVectorType.LOCAL, result.getCvssData().getAccessVector());
        assertEquals(CvssV2Data.AccessComplexityType.LOW, result.getCvssData().getAccessComplexity());
        assertEquals(CvssV2Data.AuthenticationType.NONE, result.getCvssData().getAuthentication());
        assertEquals(CvssV2Data.CiaType.NONE, result.getCvssData().getConfidentialityImpact());
        assertEquals(CvssV2Data.CiaType.NONE, result.getCvssData().getIntegrityImpact());
        assertEquals(CvssV2Data.CiaType.COMPLETE, result.getCvssData().getAvailabilityImpact());
        assertEquals("LOW", result.getCvssData().getBaseSeverity());
        assertEquals(1.0, result.getCvssData().getBaseScore(), 0);
    }

    /**
     * Test of cvssV2ScoreToSeverity method, of class CvssUtil.
     */
    @Test
    void testCvssV2ScoreToSeverity() {
        Double score = -1.0;
        String expResult = "UNKNOWN";
        String result = CvssUtil.cvssV2ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 0.0;
        expResult = "LOW";
        result = CvssUtil.cvssV2ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 1.0;
        expResult = "LOW";
        result = CvssUtil.cvssV2ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 3.9;
        expResult = "LOW";
        result = CvssUtil.cvssV2ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 4.0;
        expResult = "MEDIUM";
        result = CvssUtil.cvssV2ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 6.9;
        expResult = "MEDIUM";
        result = CvssUtil.cvssV2ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 7.0;
        expResult = "HIGH";
        result = CvssUtil.cvssV2ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 10.0;
        expResult = "HIGH";
        result = CvssUtil.cvssV2ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 11.0;
        expResult = "UNKNOWN";
        result = CvssUtil.cvssV2ScoreToSeverity(score);
        assertEquals(expResult, result);
    }

    /**
     * Test of cvssV3ScoreToSeverity method, of class CvssUtil.
     */
    @Test
    void testCvssV3ScoreToSeverity() {
        Double score = 0.0;
        CvssV3Data.SeverityType expResult = CvssV3Data.SeverityType.NONE;
        CvssV3Data.SeverityType result = CvssUtil.cvssV3ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 1.0;
        expResult = CvssV3Data.SeverityType.LOW;
        result = CvssUtil.cvssV3ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 3.9;
        expResult = CvssV3Data.SeverityType.LOW;
        result = CvssUtil.cvssV3ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 4.0;
        expResult = CvssV3Data.SeverityType.MEDIUM;
        result = CvssUtil.cvssV3ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 6.9;
        expResult = CvssV3Data.SeverityType.MEDIUM;
        result = CvssUtil.cvssV3ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 7.0;
        expResult = CvssV3Data.SeverityType.HIGH;
        result = CvssUtil.cvssV3ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 8.9;
        expResult = CvssV3Data.SeverityType.HIGH;
        result = CvssUtil.cvssV3ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 9.0;
        expResult = CvssV3Data.SeverityType.CRITICAL;
        result = CvssUtil.cvssV3ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 10.0;
        expResult = CvssV3Data.SeverityType.CRITICAL;
        result = CvssUtil.cvssV3ScoreToSeverity(score);
        assertEquals(expResult, result);

        score = 11.0;
        result = CvssUtil.cvssV3ScoreToSeverity(score);
        assertNull(result);

        score = -1.0;
        result = CvssUtil.cvssV3ScoreToSeverity(score);
        assertNull(result);
    }

    /**
     * Test of vectorToCvssV3 method, of class CvssUtil.
     */
    @Test
    void testVectorToCvssV3() {
        String vectorString = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H";
        Double baseScore = 10.0;
        CvssV3 result = CvssUtil.vectorToCvssV3(vectorString, baseScore);
        assertEquals(CvssV3Data.Version._3_1, result.getCvssData().getVersion());
        assertEquals(CvssV3Data.AttackVectorType.LOCAL, result.getCvssData().getAttackVector());
        assertEquals(CvssV3Data.AttackComplexityType.LOW, result.getCvssData().getAttackComplexity());
        assertEquals(CvssV3Data.PrivilegesRequiredType.LOW, result.getCvssData().getPrivilegesRequired());
        assertEquals(CvssV3Data.UserInteractionType.NONE, result.getCvssData().getUserInteraction());
        assertEquals(CvssV3Data.ScopeType.UNCHANGED, result.getCvssData().getScope());
        assertEquals(CvssV3Data.CiaType.NONE, result.getCvssData().getConfidentialityImpact());
        assertEquals(CvssV3Data.CiaType.NONE, result.getCvssData().getIntegrityImpact());
        assertEquals(CvssV3Data.CiaType.HIGH, result.getCvssData().getAvailabilityImpact());
        assertEquals(CvssV3Data.SeverityType.CRITICAL, result.getCvssData().getBaseSeverity());
        assertEquals(10.0, result.getCvssData().getBaseScore(), 0);
    }

}
