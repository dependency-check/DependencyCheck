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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility to estimate severity level scores.
 *
 * @author Jeremy Long
 */
public final class SeverityUtil {

    /**
     * The cutoff for high severity.
     */
    private static final Double HIGH = 10.0;
    /**
     * The cutoff for medium severity.
     */
    private static final Double MEDIUM = 6.9;
    /**
     * The cutoff for low severity.
     */
    private static final Double LOW = 3.9;
    /**
     * The cutoff for none severity.
     */
    private static final Double NONE = 0.0;
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SeverityUtil.class);

    /**
     * Private constructor for a utility class.
     */
    private SeverityUtil() {
        //noop
    }

    /**
     * Estimates the CVSS V2 Score based on a given severity. The implementation
     * will default to 3.9 if no recognized "severity" level is given (critical,
     * high, low).
     *
     * @param severity the severity text (e.g. "medium")
     * @return a score from 0 to 10
     */
    public static Double estimateCvssV2(String severity) {
        switch (severity == null ? "none" : severity.toLowerCase()) {
            case "critical":
            case "high":
                return HIGH;
            case "moderate":
            case "medium":
                return MEDIUM;
            case "info":
            case "none":
            case "informational":
                return NONE;
            case "low":
            case "unknown":
            default:
                return LOW;
        }
    }

    /**
     * Converts a textual severity to the text that should be used to signal it
     * in a report.
     *
     * @param severity The textual unscored severity
     * @return The severity when properly recognized, otherwise the severity
     * extended with a remark that it was not recognized and assumed to
     * represent a critical severity.
     */
    public static String unscoredToSeveritytext(final String severity) {
        switch (Severity.forUnscored(severity)) {
            case CRITICAL:
            case HIGH:
            case MEDIUM:
            case LOW:
            case INFO:
                return severity;
            case ASSUMED_CRITICAL:
            default:
                final String sevText;
                if ("0.0".equals(severity)) {
                    sevText = "Unknown";
                } else {
                    sevText = severity;
                }
                return sevText + " (not recognized; assumed to be critical)";
        }
    }

    /**
     * Creates an estimated sort-adjusted CVSSv3 score for an unscored textual
     * severity. For recognized severities below critical it returns a value at
     * the lower bound of the CVSSv3 baseScore for that severity. For recognized
     * critical severities it returns a score in-between the upper bound of the
     * HIGH CVSSv2 score and the lowest sort-adjusted CVSSv3 critical score, so
     * that unscored critical vulnerabilties are ordered in between CRITICAL
     * scored CVSSv3 rated vulnerabilities and HIGH-scored CVSSv2 rated
     * vulnerabilities. For unrecognized severities it returns a score
     * in-between the top HIGH CVSSv2 score and the estimatedSortAdjustedCVSSv3
     * score for an unscored severity recognized as critical, so that recognized
     * critical will win over unrecognized severities while unrecognized
     * severities are assumed to be of a critical nature.
     *
     * @param severity The textual severity, may be null
     * @return A float that can be used to numerically sort vulnerabilities in
     * approximated severity (highest float represents highest severity).
     * @see #sortAdjustedCVSSv3BaseScore(Double)
     */
    public static Double estimatedSortAdjustedCVSSv3(final String severity) {
        switch (Severity.forUnscored(severity)) {
            case CRITICAL:
                return 10.2;
            case HIGH:
                return 7.0;
            case MEDIUM:
                return 4.0;
            case LOW:
                return 0.1;
            case INFO:
                return 0.0;
            case ASSUMED_CRITICAL:
            default:
                SeverityUtil.LOGGER.debug("Unrecognized unscored textual severity: {}, assuming critical score as worst-case "
                        + "estimate for sorting",
                        severity);
                return 10.1;
        }
    }

    /**
     * Compute an adjusted CVSSv3 baseScore that ensures that CRITICAL CVSSv3
     * scores will win over HIGH CVSSv2 and CRITICAL unscored severities to
     * allow for a best-effort sorting that enables the report to list a
     * reliable 'highest severity' in the report.
     *
     * @param cvssV3BaseScore The cvssV3 baseScore severity of a vulnerability
     * @return The cvssV3 baseScore, adjusted if necessary in order to guarantee
     * that CVSSv3 CRITICAL scores will rate higher than CVSSv2 HIGH, unscored
     * critical severities and unscored unrecognized severities (which are
     * assumed for sorting to be of a critical nature)
     * @see #estimatedSortAdjustedCVSSv3(String)
     */
    public static Double sortAdjustedCVSSv3BaseScore(final Double cvssV3BaseScore) {
        if (cvssV3BaseScore.floatValue() >= 9.0f) {
            return cvssV3BaseScore + 1.3;
        }
        return cvssV3BaseScore;
    }

    /**
     * An enum to translate unscored severity texts to a severity level of a
     * defined set of severities. Allows for re-use of the text-to-severity
     * mapping in multiple helper methods.
     */
    private enum Severity {
        /**
         * A severity level for textual values that should be regarded as
         * accompanying a critical severity vulnerability
         */
        CRITICAL,
        /**
         * A severity level for textual values that are not recognized and
         * therefor assumed to be accompanying a critical severity vulnerability
         */
        ASSUMED_CRITICAL,
        /**
         * A severity level for textual values that should be regarded as
         * accompanying a high severity vulnerability
         */
        HIGH,
        /**
         * A severity level for textual values that should be regarded as
         * accompanying a medium severity vulnerability
         */
        MEDIUM,
        /**
         * A severity level for textual values that should be regarded as
         * accompanying a low severity vulnerability
         */
        LOW,
        /**
         * A severity level for textual values that should be regarded as
         * accompanying a vulnerability of informational nature
         */
        INFO;

        public static Severity forUnscored(String value) {
            switch (value == null ? "none" : value.toLowerCase()) {
                case "critical":
                    return CRITICAL;
                case "high":
                    return HIGH;
                case "moderate":
                case "medium":
                    return MEDIUM;
                case "info":
                case "informational":
                    return INFO;
                case "low":
                case "unknown":
                case "none":
                    return LOW;
                default:
                    return ASSUMED_CRITICAL;
            }
        }
    }
}
