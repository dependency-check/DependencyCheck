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
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4Data;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
        assertEquals("UNKNOWN", CvssUtil.cvssV2ScoreToSeverity(-1.0));
        assertEquals("LOW", CvssUtil.cvssV2ScoreToSeverity(0.0));
        assertEquals("LOW", CvssUtil.cvssV2ScoreToSeverity(0.05));
        assertEquals("LOW", CvssUtil.cvssV2ScoreToSeverity(1.0));
        assertEquals("LOW", CvssUtil.cvssV2ScoreToSeverity(3.9));
        assertEquals("MEDIUM", CvssUtil.cvssV2ScoreToSeverity(4.0));
        assertEquals("MEDIUM", CvssUtil.cvssV2ScoreToSeverity(6.9));
        assertEquals("MEDIUM", CvssUtil.cvssV2ScoreToSeverity((double) 6.9f)); // test low-precision floating point values
        assertEquals("HIGH", CvssUtil.cvssV2ScoreToSeverity(7.0));
        assertEquals("HIGH", CvssUtil.cvssV2ScoreToSeverity(10.0));
        assertEquals("UNKNOWN", CvssUtil.cvssV2ScoreToSeverity(11.0));
    }

    /**
     * Test of cvssV3ScoreToSeverity method, of class CvssUtil.
     */
    @Test
    void testCvssV3ScoreToSeverity() {
        assertEquals(CvssV3Data.SeverityType.NONE, CvssUtil.cvssV3ScoreToSeverity(0.0));
        assertEquals(CvssV3Data.SeverityType.LOW, CvssUtil.cvssV3ScoreToSeverity(0.05));
        assertEquals(CvssV3Data.SeverityType.LOW, CvssUtil.cvssV3ScoreToSeverity(1.0));
        assertEquals(CvssV3Data.SeverityType.LOW, CvssUtil.cvssV3ScoreToSeverity(3.9));
        assertEquals(CvssV3Data.SeverityType.MEDIUM, CvssUtil.cvssV3ScoreToSeverity(4.0));
        assertEquals(CvssV3Data.SeverityType.MEDIUM, CvssUtil.cvssV3ScoreToSeverity(6.9));
        assertEquals(CvssV3Data.SeverityType.MEDIUM, CvssUtil.cvssV3ScoreToSeverity((double) 6.9f)); // test low-precision floating point values
        assertEquals(CvssV3Data.SeverityType.HIGH, CvssUtil.cvssV3ScoreToSeverity(7.0));
        assertEquals(CvssV3Data.SeverityType.HIGH, CvssUtil.cvssV3ScoreToSeverity(8.9));
        assertEquals(CvssV3Data.SeverityType.CRITICAL, CvssUtil.cvssV3ScoreToSeverity(9.0));
        assertEquals(CvssV3Data.SeverityType.CRITICAL, CvssUtil.cvssV3ScoreToSeverity(10.0));
        assertNull(CvssUtil.cvssV3ScoreToSeverity(11.0));
        assertNull(CvssUtil.cvssV3ScoreToSeverity(-1.0));
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

    /**
     * Test of cvssV4ScoreToSeverity method, of class CvssUtil.
     */
    @Test
    void testCvssV4ScoreToSeverity() {
        assertEquals(CvssV4Data.SeverityType.NONE, CvssUtil.cvssV4ScoreToSeverity(0.0));
        assertEquals(CvssV4Data.SeverityType.LOW, CvssUtil.cvssV4ScoreToSeverity(0.05));
        assertEquals(CvssV4Data.SeverityType.LOW, CvssUtil.cvssV4ScoreToSeverity(1.0));
        assertEquals(CvssV4Data.SeverityType.LOW, CvssUtil.cvssV4ScoreToSeverity(3.9));
        assertEquals(CvssV4Data.SeverityType.MEDIUM, CvssUtil.cvssV4ScoreToSeverity(4.0));
        assertEquals(CvssV4Data.SeverityType.MEDIUM, CvssUtil.cvssV4ScoreToSeverity(6.9));
        assertEquals(CvssV4Data.SeverityType.MEDIUM, CvssUtil.cvssV4ScoreToSeverity(6.9f)); // test low-precision floating point values
        assertEquals(CvssV4Data.SeverityType.HIGH, CvssUtil.cvssV4ScoreToSeverity(7.0));
        assertEquals(CvssV4Data.SeverityType.HIGH, CvssUtil.cvssV4ScoreToSeverity(8.9));
        assertEquals(CvssV4Data.SeverityType.CRITICAL, CvssUtil.cvssV4ScoreToSeverity(9.0));
        assertEquals(CvssV4Data.SeverityType.CRITICAL, CvssUtil.cvssV4ScoreToSeverity(10.0));
        assertThrows(IllegalArgumentException.class, () -> CvssUtil.cvssV4ScoreToSeverity(11.0));
        assertThrows(IllegalArgumentException.class, () -> CvssUtil.cvssV4ScoreToSeverity(-1.0));
    }

    /**
     * Test of vectorToCvssV4 method, of class CvssUtil.
     */
    @Test
    void testVectorToCvssV4() {
        String vectorString = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N";
        Double baseScore = 8.2;
        String source = "ossIndex";
        CvssV4.Type type = CvssV4.Type.PRIMARY;
        CvssV4 result = CvssUtil.vectorToCvssV4(source, type, baseScore, vectorString);
        assertEquals(CvssV4Data.Version._4_0, result.getCvssData().getVersion());
        assertEquals(source, result.getSource());
        assertEquals(type, result.getType());
        assertEquals(CvssV4Data.AttackVectorType.NETWORK, result.getCvssData().getAttackVector());
        assertEquals(CvssV4Data.AttackComplexityType.LOW, result.getCvssData().getAttackComplexity());
        assertEquals(CvssV4Data.AttackRequirementsType.PRESENT, result.getCvssData().getAttackRequirements());
        assertEquals(CvssV4Data.PrivilegesRequiredType.NONE, result.getCvssData().getPrivilegesRequired());
        assertEquals(CvssV4Data.UserInteractionType.NONE, result.getCvssData().getUserInteraction());
        assertEquals(CvssV4Data.CiaType.HIGH, result.getCvssData().getVulnConfidentialityImpact());
        assertEquals(CvssV4Data.CiaType.NONE, result.getCvssData().getVulnIntegrityImpact());
        assertEquals(CvssV4Data.CiaType.NONE, result.getCvssData().getVulnAvailabilityImpact());
        assertEquals(CvssV4Data.CiaType.NONE, result.getCvssData().getSubConfidentialityImpact());
        assertEquals(CvssV4Data.CiaType.NONE, result.getCvssData().getSubIntegrityImpact());
        assertEquals(CvssV4Data.CiaType.NONE, result.getCvssData().getSubAvailabilityImpact());
        assertEquals(CvssV4Data.SeverityType.HIGH, result.getCvssData().getBaseSeverity());
        assertEquals(8.2, result.getCvssData().getBaseScore(), 0);
    }

}
