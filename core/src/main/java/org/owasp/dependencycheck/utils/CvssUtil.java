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
}
