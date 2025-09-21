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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV4;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4Data;
import org.sonatype.ossindex.service.api.cvss.Cvss3Severity;

/**
 * Utility class to create CVSS Objects.
 *
 * @author Jeremy Long
 */
public final class CvssUtil {

    private CvssUtil() {
        //empty constructor for utility class.
    }

    /**
     * The CVSS v3 Base Metrics (that are required by the spec for any CVSS v3
     * Vector String)
     */
    private static final List<String> BASE_METRICS_V3 = Arrays.asList("AV", "AC", "PR", "UI", "S", "C", "I", "A");

    /**
     * The CVSS V2 Metrics required for the vector string to be complete.
     */
    private static final List<String> BASE_METRICS_V2 = Arrays.asList("AV", "AC", "Au", "C", "I", "A");
    /**
     * ZERO.
     */
    private static final Double ZERO = 0.0;
    /**
     * ONE.
     */
    private static final Double ONE = 1.0;
    /**
     * FOUR.
     */
    private static final Double FOUR = 4.0;
    /**
     * SEVEN.
     */
    private static final Double SEVEN = 7.0;
    /**
     * NINE.
     */
    private static final Double NINE = 9.0;
    /**
     * TEN.
     */
    private static final Double TEN = 10.0;
    /**
     * UNKNOWN.
     */
    private static final String UNKNOWN = "UNKNOWN";
    /**
     * HIGH.
     */
    private static final String HIGH = "HIGH";
    /**
     * MEDIUM.
     */
    private static final String MEDIUM = "MEDIUM";
    /**
     * LOW.
     */
    private static final String LOW = "LOW";

    /**
     * Convert a CVSSv2 vector String into a CvssV3 Object.
     *
     * @param vectorString the vector string
     * @param baseScore the base score
     * @return the CVSSv2 object
     */
    public static CvssV2 vectorToCvssV2(String vectorString, Double baseScore) {
        if (vectorString.startsWith("CVSS:")) {
            throw new IllegalArgumentException("Not a valid CVSSv2 vector string: " + vectorString);
        }
        final String[] metricStrings = vectorString.substring(vectorString.indexOf('/') + 1).split("/");
        final HashMap<String, String> metrics = new HashMap<>();
        for (int i = 0; i < metricStrings.length; i++) {
            final String[] metricKeyVal = metricStrings[i].split(":");
            if (metricKeyVal.length != 2) {
                throw new IllegalArgumentException(
                        String.format("Not a valid CVSSv2 vector string '%s', invalid metric component '%s'",
                                vectorString, metricStrings[i]));
            }
            metrics.put(metricKeyVal[0], metricKeyVal[1]);
        }
        if (!metrics.keySet().containsAll(BASE_METRICS_V2)) {
            throw new IllegalArgumentException(
                    String.format("Not a valid CVSSv2 vector string '%s'; missing one or more required Metrics;",
                            vectorString));
        }

        //"AV:L/AC:L/Au:N/C:N/I:N/A:C"
        final CvssV2Data.AccessVectorType accessVector = CvssV2Data.AccessVectorType.fromValue(metrics.get("AV"));
        final CvssV2Data.AccessComplexityType attackComplexity = CvssV2Data.AccessComplexityType.fromValue(metrics.get("AC"));
        final CvssV2Data.AuthenticationType authentication = CvssV2Data.AuthenticationType.fromValue(metrics.get("Au"));
        final CvssV2Data.CiaType confidentialityImpact = CvssV2Data.CiaType.fromValue(metrics.get("C"));
        final CvssV2Data.CiaType integrityImpact = CvssV2Data.CiaType.fromValue(metrics.get("I"));
        final CvssV2Data.CiaType availabilityImpact = CvssV2Data.CiaType.fromValue(metrics.get("A"));

        final String baseSeverity = cvssV2ScoreToSeverity(baseScore);
        final CvssV2Data data = new CvssV2Data(CvssV2Data.Version._2_0, vectorString, accessVector, attackComplexity,
                authentication, confidentialityImpact, integrityImpact, availabilityImpact, baseScore, baseSeverity,
                null, null, null, null, null, null, null, null, null, null);
        final CvssV2 cvss = new CvssV2(null, null, data, baseSeverity, null, null, null, null, null, null, null);
        return cvss;

    }

    /**
     * Determines the severity from the score.
     *
     * @param score the score
     * @return the severity
     */
    public static String cvssV2ScoreToSeverity(Double score) {
        if (score != null) {
            if (ZERO.compareTo(score) <= 0 && FOUR.compareTo(score) > 0) {
                return LOW;
            } else if (FOUR.compareTo(score) <= 0 && SEVEN.compareTo(score) > 0) {
                return MEDIUM;
            } else if (SEVEN.compareTo(score) <= 0 && TEN.compareTo(score) >= 0) {
                return HIGH;
            }
        }
        return UNKNOWN;
    }

    /**
     * Determines the severity from the score.
     *
     * @param score the score
     * @return the severity
     */
    public static CvssV3Data.SeverityType cvssV3ScoreToSeverity(Double score) {
        if (score != null) {
            if (ZERO.compareTo(score) == 0) {
                return CvssV3Data.SeverityType.NONE;
            } else if (ZERO.compareTo(score) <= 0 && FOUR.compareTo(score) > 0) {
                return CvssV3Data.SeverityType.LOW;
            } else if (FOUR.compareTo(score) <= 0 && SEVEN.compareTo(score) > 0) {
                return CvssV3Data.SeverityType.MEDIUM;
            } else if (SEVEN.compareTo(score) <= 0 && NINE.compareTo(score) > 0) {
                return CvssV3Data.SeverityType.HIGH;
            } else if (NINE.compareTo(score) <= 0 && TEN.compareTo(score) >= 0) {
                return CvssV3Data.SeverityType.CRITICAL;
            }
        }
        return null;
    }

    /**
     * Convert a CVSSv3 vector String into a CvssV3 Object.
     *
     * @param vectorString the vector string
     * @param baseScore the base score
     * @return the CVSSv3 object
     */
    public static CvssV3 vectorToCvssV3(String vectorString, Double baseScore) {
        if (!vectorString.startsWith("CVSS:3")) {
            throw new IllegalArgumentException("Not a valid CVSSv3 vector string: " + vectorString);
        }
        final String versionString = vectorString.substring(5, vectorString.indexOf('/'));
        final String[] metricStrings = vectorString.substring(vectorString.indexOf('/') + 1).split("/");
        final HashMap<String, String> metrics = new HashMap<>();
        for (int i = 0; i < metricStrings.length; i++) {
            final String[] metricKeyVal = metricStrings[i].split(":");
            if (metricKeyVal.length != 2) {
                throw new IllegalArgumentException(
                        String.format("Not a valid CVSSv3 vector string '%s', invalid metric component '%s'",
                                vectorString, metricStrings[i]));
            }
            metrics.put(metricKeyVal[0], metricKeyVal[1]);
        }
        if (!metrics.keySet().containsAll(BASE_METRICS_V3)) {
            throw new IllegalArgumentException(
                    String.format("Not a valid CVSSv3 vector string '%s'; missing one or more required Base Metrics;",
                            vectorString));
        }

        final CvssV3Data.Version version = CvssV3Data.Version.fromValue(versionString);
        //"CVSS:3.1\/AV:L\/AC:L\/PR:L\/UI:N\/S:U\/C:N\/I:N\/A:H"
        final CvssV3Data.AttackVectorType attackVector = CvssV3Data.AttackVectorType.fromValue(metrics.get("AV"));
        final CvssV3Data.AttackComplexityType attackComplexity = CvssV3Data.AttackComplexityType.fromValue(metrics.get("AC"));
        final CvssV3Data.PrivilegesRequiredType privilegesRequired = CvssV3Data.PrivilegesRequiredType.fromValue(metrics.get("PR"));
        final CvssV3Data.UserInteractionType userInteraction = CvssV3Data.UserInteractionType.fromValue(metrics.get("UI"));
        final CvssV3Data.ScopeType scope = CvssV3Data.ScopeType.fromValue(metrics.get("S"));
        final CvssV3Data.CiaType confidentialityImpact = CvssV3Data.CiaType.fromValue(metrics.get("C"));
        final CvssV3Data.CiaType integrityImpact = CvssV3Data.CiaType.fromValue(metrics.get("I"));
        final CvssV3Data.CiaType availabilityImpact = CvssV3Data.CiaType.fromValue(metrics.get("A"));

        final String baseSeverityString = Cvss3Severity.of(baseScore.floatValue()).name();
        final CvssV3Data.SeverityType baseSeverity = CvssV3Data.SeverityType.fromValue(baseSeverityString);
        final CvssV3Data data = new CvssV3Data(version, vectorString, attackVector, attackComplexity,
                privilegesRequired, userInteraction, scope, confidentialityImpact, integrityImpact, availabilityImpact, baseScore,
                baseSeverity, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null);
        final CvssV3 cvss = new CvssV3(null, null, data, null, null);
        return cvss;
    }

    public static CvssV4Data.SeverityType cvssV4ScoreToSeverity(double baseScore) {
        if (baseScore == 0.0) {
            return CvssV4Data.SeverityType.NONE;
        } else if (baseScore > 0.0 && baseScore < 4.0) {
            return CvssV4Data.SeverityType.LOW;
        } else if (baseScore >= 4.0 && baseScore < 7.0) {
            return CvssV4Data.SeverityType.MEDIUM;
        } else if (baseScore >= 7.0 && baseScore < 9.0) {
            return CvssV4Data.SeverityType.HIGH;
        } else if (baseScore >= 9.0 && baseScore <= 10.0) {
            return CvssV4Data.SeverityType.CRITICAL;
        } else {
            throw new IllegalArgumentException("Invalid CVSS base score: " + baseScore);
        }
    }

    /**
     * Convert a CVSSv4 vector String into a CvssV4 Object.
     *
     * @param source the source of the CVSS data
     * @param type the type of CVSS data (primary or secondary)
     * @param baseScore the base score
     * @param vectorString the vector string
     * @return the CVSSv4 object
     */
    public static CvssV4 vectorToCvssV4(String source, CvssV4.Type type, Double baseScore, String vectorString) {
        // Remove "CVSS:" prefix and split by "/"
        String[] parts = vectorString.replaceFirst("^CVSS:", "").split("/");
        Map<String, String> values = new HashMap<>();
        for (String part : parts) {
            String[] kv = part.split(":");
            if (kv.length == 2) {
                values.put(kv[0], kv[1]);
            }
        }

        CvssV4Data.Version version = CvssV4Data.Version.fromValue(values.getOrDefault("4.0", "4.0"));

        CvssV4Data.AttackVectorType attackVector = values.containsKey("AV") ? CvssV4Data.AttackVectorType.fromValue(values.get("AV")) : null;
        CvssV4Data.AttackComplexityType attackComplexity = values.containsKey("AC") ? CvssV4Data.AttackComplexityType.fromValue(values.get("AC")) : null;
        CvssV4Data.AttackRequirementsType attackRequirements = values.containsKey("AT") ? CvssV4Data.AttackRequirementsType.fromValue(values.get("AT")) : null;
        CvssV4Data.PrivilegesRequiredType privilegesRequired = values.containsKey("PR") ? CvssV4Data.PrivilegesRequiredType.fromValue(values.get("PR")) : null;
        CvssV4Data.UserInteractionType userInteraction = values.containsKey("UI") ? CvssV4Data.UserInteractionType.fromValue(values.get("UI")) : null;
        CvssV4Data.CiaType vulnConfidentialityImpact = values.containsKey("VC") ? CvssV4Data.CiaType.fromValue(values.get("VC")) : null;
        CvssV4Data.CiaType vulnIntegrityImpact = values.containsKey("VI") ? CvssV4Data.CiaType.fromValue(values.get("VI")) : null;
        CvssV4Data.CiaType vulnAvailabilityImpact = values.containsKey("VA") ? CvssV4Data.CiaType.fromValue(values.get("VA")) : null;
        CvssV4Data.CiaType subConfidentialityImpact = values.containsKey("SC") ? CvssV4Data.CiaType.fromValue(values.get("SC")) : null;
        CvssV4Data.CiaType subIntegrityImpact = values.containsKey("SI") ? CvssV4Data.CiaType.fromValue(values.get("SI")) : null;
        CvssV4Data.CiaType subAvailabilityImpact = values.containsKey("SA") ? CvssV4Data.CiaType.fromValue(values.get("SA")) : null;
        CvssV4Data.ExploitMaturityType exploitMaturity = values.containsKey("E") ? CvssV4Data.ExploitMaturityType.fromValue(values.get("E")) : CvssV4Data.ExploitMaturityType.NOT_DEFINED;
        CvssV4Data.CiaRequirementType confidentialityRequirement = values.containsKey("CR") ? CvssV4Data.CiaRequirementType.fromValue(values.get("CR")) : CvssV4Data.CiaRequirementType.NOT_DEFINED;
        CvssV4Data.CiaRequirementType integrityRequirement = values.containsKey("IR") ? CvssV4Data.CiaRequirementType.fromValue(values.get("IR")) : CvssV4Data.CiaRequirementType.NOT_DEFINED;
        CvssV4Data.CiaRequirementType availabilityRequirement = values.containsKey("AR") ? CvssV4Data.CiaRequirementType.fromValue(values.get("AR")) : CvssV4Data.CiaRequirementType.NOT_DEFINED;
        CvssV4Data.ModifiedAttackVectorType modifiedAttackVector = values.containsKey("MAV") ? CvssV4Data.ModifiedAttackVectorType.fromValue(values.get("MAV")) : CvssV4Data.ModifiedAttackVectorType.NOT_DEFINED;
        CvssV4Data.ModifiedAttackComplexityType modifiedAttackComplexity = values.containsKey("MAC") ? CvssV4Data.ModifiedAttackComplexityType.fromValue(values.get("MAC")) : CvssV4Data.ModifiedAttackComplexityType.NOT_DEFINED;
        CvssV4Data.ModifiedAttackRequirementsType modifiedAttackRequirements = values.containsKey("MAT") ? CvssV4Data.ModifiedAttackRequirementsType.fromValue(values.get("MAT")) : CvssV4Data.ModifiedAttackRequirementsType.NOT_DEFINED;
        CvssV4Data.ModifiedPrivilegesRequiredType modifiedPrivilegesRequired = values.containsKey("MPR") ? CvssV4Data.ModifiedPrivilegesRequiredType.fromValue(values.get("MPR")) : CvssV4Data.ModifiedPrivilegesRequiredType.NOT_DEFINED;
        CvssV4Data.ModifiedUserInteractionType modifiedUserInteraction = values.containsKey("MUI") ? CvssV4Data.ModifiedUserInteractionType.fromValue(values.get("MUI")) : CvssV4Data.ModifiedUserInteractionType.NOT_DEFINED;
        CvssV4Data.ModifiedCiaType modifiedVulnConfidentialityImpact = values.containsKey("MVC") ? CvssV4Data.ModifiedCiaType.fromValue(values.get("MVC")) : CvssV4Data.ModifiedCiaType.NOT_DEFINED;
        CvssV4Data.ModifiedCiaType modifiedVulnIntegrityImpact = values.containsKey("MVI") ? CvssV4Data.ModifiedCiaType.fromValue(values.get("MVI")) : CvssV4Data.ModifiedCiaType.NOT_DEFINED;
        CvssV4Data.ModifiedCiaType modifiedVulnAvailabilityImpact = values.containsKey("MVA") ? CvssV4Data.ModifiedCiaType.fromValue(values.get("MVA")) : CvssV4Data.ModifiedCiaType.NOT_DEFINED;
        CvssV4Data.ModifiedSubCType modifiedSubConfidentialityImpact = values.containsKey("MSC") ? CvssV4Data.ModifiedSubCType.fromValue(values.get("MSC")) : CvssV4Data.ModifiedSubCType.NOT_DEFINED;
        CvssV4Data.ModifiedSubIaType modifiedSubIntegrityImpact = values.containsKey("MSI") ? CvssV4Data.ModifiedSubIaType.fromValue(values.get("MSI")) : CvssV4Data.ModifiedSubIaType.NOT_DEFINED;
        CvssV4Data.ModifiedSubIaType modifiedSubAvailabilityImpact = values.containsKey("MSA") ? CvssV4Data.ModifiedSubIaType.fromValue(values.get("MSA")) : CvssV4Data.ModifiedSubIaType.NOT_DEFINED;
        CvssV4Data.SafetyType safety = values.containsKey("S") ? CvssV4Data.SafetyType.fromValue(values.get("S")) : CvssV4Data.SafetyType.NOT_DEFINED;
        CvssV4Data.AutomatableType automatable = values.containsKey("AU") ? CvssV4Data.AutomatableType.fromValue(values.get("AU")) : CvssV4Data.AutomatableType.NOT_DEFINED;
        CvssV4Data.RecoveryType recovery = values.containsKey("R") ? CvssV4Data.RecoveryType.fromValue(values.get("R")) : CvssV4Data.RecoveryType.NOT_DEFINED;
        CvssV4Data.ValueDensityType valueDensity = values.containsKey("V") ? CvssV4Data.ValueDensityType.fromValue(values.get("V")) : CvssV4Data.ValueDensityType.NOT_DEFINED;
        CvssV4Data.VulnerabilityResponseEffortType vulnerabilityResponseEffort = values.containsKey("RE") ? CvssV4Data.VulnerabilityResponseEffortType.fromValue(values.get("RE")) : CvssV4Data.VulnerabilityResponseEffortType.NOT_DEFINED;
        CvssV4Data.ProviderUrgencyType providerUrgency = values.containsKey("U") ? CvssV4Data.ProviderUrgencyType.fromValue(values.get("U")) : CvssV4Data.ProviderUrgencyType.NOT_DEFINED;

        CvssV4Data.SeverityType baseSeverity = cvssV4ScoreToSeverity(baseScore);
        // Scores and severities are not present in the vector string, set to null/defaults
        Double threatScore = null;
        CvssV4Data.SeverityType threatSeverity = null;
        Double environmentalScore = null;
        CvssV4Data.SeverityType environmentalSeverity = null;

        CvssV4Data cvssData = new CvssV4Data(
                version,
                vectorString,
                attackVector,
                attackComplexity,
                attackRequirements,
                privilegesRequired,
                userInteraction,
                vulnConfidentialityImpact,
                vulnIntegrityImpact,
                vulnAvailabilityImpact,
                subConfidentialityImpact,
                subIntegrityImpact,
                subAvailabilityImpact,
                exploitMaturity,
                confidentialityRequirement,
                integrityRequirement,
                availabilityRequirement,
                modifiedAttackVector,
                modifiedAttackComplexity,
                modifiedAttackRequirements,
                modifiedPrivilegesRequired,
                modifiedUserInteraction,
                modifiedVulnConfidentialityImpact,
                modifiedVulnIntegrityImpact,
                modifiedVulnAvailabilityImpact,
                modifiedSubConfidentialityImpact,
                modifiedSubIntegrityImpact,
                modifiedSubAvailabilityImpact,
                safety,
                automatable,
                recovery,
                valueDensity,
                vulnerabilityResponseEffort,
                providerUrgency,
                baseScore,
                baseSeverity,
                threatScore,
                threatSeverity,
                environmentalScore,
                environmentalSeverity
        );

        return new CvssV4(source, type, cvssData);
    }
}
