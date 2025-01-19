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
 * Copyright (c) 2022 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.reporting;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV2;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4;

/**
 *
 * @author Jeremy Long
 */
public class SarifRule {

    /**
     * The rule id.
     */
    private String id;
    /**
     * The short description.
     */
    private String shortDescription;
    /**
     * The full description.
     */
    private String fullDescription;
    /**
     * The name of the rule.
     */
    private String name;
    /**
     * CVSS V2 field.
     */
    private String cvssv2Score;
    /**
     * CVSS V2 field.
     */
    private String cvssv2AccessVector;
    /**
     * CVSS V2 field.
     */
    private String cvssv2AccessComplexity;
    /**
     * CVSS V2 field.
     */
    private String cvssv2Authentication;
    /**
     * CVSS V2 field.
     */
    private String cvssv2ConfidentialityImpact;
    /**
     * CVSS V2 field.
     */
    private String cvssv2IntegrityImpact;
    /**
     * CVSS V2 field.
     */
    private String cvssv2AvailabilityImpact;
    /**
     * CVSS V2 field.
     */
    private String cvssv2Severity;
    /**
     * CVSS V2 field.
     */
    private String cvssv2Version;
    /**
     * CVSS V2 field.
     */
    private String cvssv2ExploitabilityScore;
    /**
     * CVSS V2 field.
     */
    private String cvssv2ImpactScore;
    /**
     * CVSS V3 field.
     */
    private String cvssv3BaseScore;
    /**
     * CVSS V3 field.
     */
    private String cvssv3AttackVector;
    /**
     * CVSS V3 field.
     */
    private String cvssv3AttackComplexity;
    /**
     * CVSS V3 field.
     */
    private String cvssv3PrivilegesRequired;
    /**
     * CVSS V3 field.
     */
    private String cvssv3UserInteraction;
    /**
     * CVSS V3 field.
     */
    private String cvssv3Scope;
    /**
     * CVSS V3 field.
     */
    private String cvssv3ConfidentialityImpact;
    /**
     * CVSS V3 field.
     */
    private String cvssv3IntegrityImpact;
    /**
     * CVSS V3 field.
     */
    private String cvssv3AvailabilityImpact;
    /**
     * CVSS V3 field.
     */
    private String cvssv3BaseSeverity;
    /**
     * CVSS V3 field.
     */
    private String cvssv3ExploitabilityScore;
    /**
     * CVSS V3 field.
     */
    private String cvssv3ImpactScore;
    /**
     * CVSS V3 field.
     */
    private String cvssv3Version;
    /**
     * CVSS V4 field.
     */
    private String cvssv4BaseScore;
    /**
     * CVSS V4 Vector.
     */
    private String cvssv4Vector;
    /**
     * The source of the rule.
     */
    private String source;

    /**
     * Constructs a new SARIF rule object.
     *
     * @param name the name of the rule
     * @param shortDescription the short description
     * @param fullDescription the full description
     * @param source the source
     * @param cvssV2 the CVSS v2 score
     * @param cvssV3 the CVSS v3 score
     * @param cvssV4 the CVSS v4 score
     */
    public SarifRule(String name, String shortDescription, String fullDescription,
                     String source, CvssV2 cvssV2, CvssV3 cvssV3, CvssV4 cvssV4) {
        this.id = name;
        this.name = name;
        this.shortDescription = shortDescription;
        this.fullDescription = fullDescription;
        this.source = source;
        if (cvssV2 != null) {
            if (cvssV2.getCvssData().getBaseScore() != null) {
                this.cvssv2Score = cvssV2.getCvssData().getBaseScore().toString();
            }
            if (cvssV2.getCvssData().getAccessVector() != null) {
                this.cvssv2AccessVector = cvssV2.getCvssData().getAccessVector().name();
            }
            if (cvssV2.getCvssData().getAccessComplexity() != null) {
                this.cvssv2AccessComplexity = cvssV2.getCvssData().getAccessComplexity().name();
            }
            if (cvssV2.getCvssData().getAuthentication() != null) {
                this.cvssv2Authentication = cvssV2.getCvssData().getAuthentication().name();
            }
            if (cvssV2.getCvssData().getConfidentialityImpact() != null) {
                this.cvssv2ConfidentialityImpact = cvssV2.getCvssData().getConfidentialityImpact().name();
            }
            if (cvssV2.getCvssData().getIntegrityImpact() != null) {
                this.cvssv2IntegrityImpact = cvssV2.getCvssData().getIntegrityImpact().name();
            }
            if (cvssV2.getCvssData().getAvailabilityImpact() != null) {
                this.cvssv2AvailabilityImpact = cvssV2.getCvssData().getAvailabilityImpact().name();
            }
            this.cvssv2Severity = cvssV2.getCvssData().getBaseSeverity();
            if (cvssV2.getCvssData().getVersion() != null) {
                this.cvssv2Version = cvssV2.getCvssData().getVersion().name();
            }
            if (cvssV2.getExploitabilityScore() != null) {
                this.cvssv2ExploitabilityScore = cvssV2.getExploitabilityScore().toString();
            }
            if (cvssV2.getImpactScore() != null) {
                this.cvssv2ImpactScore = cvssV2.getImpactScore().toString();
            }
        }
        if (cvssV3 != null) {
            if (cvssV3.getCvssData().getBaseScore() != null) {
                this.cvssv3BaseScore = cvssV3.getCvssData().getBaseScore().toString();
            }
            if (cvssV3.getCvssData().getAttackVector() != null) {
                this.cvssv3AttackVector = cvssV3.getCvssData().getAttackVector().name();
            }
            if (cvssV3.getCvssData().getAttackComplexity() != null) {
                this.cvssv3AttackComplexity = cvssV3.getCvssData().getAttackComplexity().name();
            }
            if (cvssV3.getCvssData().getPrivilegesRequired() != null) {
                this.cvssv3PrivilegesRequired = cvssV3.getCvssData().getPrivilegesRequired().name();
            }
            if (cvssV3.getCvssData().getUserInteraction() != null) {
                this.cvssv3UserInteraction = cvssV3.getCvssData().getUserInteraction().name();
            }
            if (cvssV3.getCvssData().getScope() != null) {
                this.cvssv3Scope = cvssV3.getCvssData().getScope().name();
            }
            if (cvssV3.getCvssData().getConfidentialityImpact() != null) {
                this.cvssv3ConfidentialityImpact = cvssV3.getCvssData().getConfidentialityImpact().name();
            }
            if (cvssV3.getCvssData().getIntegrityImpact() != null) {
                this.cvssv3IntegrityImpact = cvssV3.getCvssData().getIntegrityImpact().name();
            }
            if (cvssV3.getCvssData().getAvailabilityImpact() != null) {
                this.cvssv3AvailabilityImpact = cvssV3.getCvssData().getAvailabilityImpact().name();
            }
            if (cvssV3.getCvssData().getBaseSeverity() != null) {
                this.cvssv3BaseSeverity = cvssV3.getCvssData().getBaseSeverity().name();
            }
            if (cvssV3.getExploitabilityScore() != null) {
                this.cvssv3ExploitabilityScore = cvssV3.getExploitabilityScore().toString();
            }
            if (cvssV3.getImpactScore() != null) {
                this.cvssv3ImpactScore = cvssV3.getImpactScore().toString();
            }
            this.cvssv3Version = cvssV3.getCvssData().getVersion().name();
        }
        if (cvssV4 != null && cvssV4.getCvssData() != null) {
            if (cvssV4.getCvssData().getBaseScore() != null) {
                this.cvssv4BaseScore = cvssV4.getCvssData().getBaseScore().toString();
            }
            this.cvssv4Vector = cvssV4.toString();
        }
    }

    /**
     * Get the value of source.
     *
     * @return the value of source
     */
    public String getSource() {
        return source;
    }

    /**
     * Set the value of source.
     *
     * @param source new value of source
     */
    public void setSource(String source) {
        this.source = source;
    }

    /**
     * Get the value of CVSS3 Version.
     *
     * @return the value of CVSS3 Version
     */
    public String getCvssv3Version() {
        return cvssv3Version;
    }

    /**
     * Set the value of CVSS3 Version.
     *
     * @param cvssv3Version new value of CVSS3 Version
     */
    public void setCvssv3Version(String cvssv3Version) {
        this.cvssv3Version = cvssv3Version;
    }

    /**
     * Get the value of CVSS3 Impact Score.
     *
     * @return the value of CVSS3 Impact Score
     */
    public String getCvssv3ImpactScore() {
        return cvssv3ImpactScore;
    }

    /**
     * Set the value of CVSS3 Impact Score.
     *
     * @param cvssv3ImpactScore new value of CVSS3 Impact Score
     */
    public void setCvssv3ImpactScore(String cvssv3ImpactScore) {
        this.cvssv3ImpactScore = cvssv3ImpactScore;
    }

    /**
     * Get the value of CVSS3 Exploitability Score.
     *
     * @return the value of CVSS3 Exploitability Score
     */
    public String getCvssv3ExploitabilityScore() {
        return cvssv3ExploitabilityScore;
    }

    /**
     * Set the value of CVSS3 Exploitability Score.
     *
     * @param cvssv3ExploitabilityScore new value of CVSS3 Exploitability Score
     */
    public void setCvssv3ExploitabilityScore(String cvssv3ExploitabilityScore) {
        this.cvssv3ExploitabilityScore = cvssv3ExploitabilityScore;
    }

    /**
     * Get the value of CVSS3 Base Severity.
     *
     * @return the value of CVSS3 Base Severity
     */
    public String getCvssv3BaseSeverity() {
        return cvssv3BaseSeverity;
    }

    /**
     * Set the value of CVSS3 Base Severity.
     *
     * @param cvssv3BaseSeverity new value of CVSS3 Base Severity
     */
    public void setCvssv3BaseSeverity(String cvssv3BaseSeverity) {
        this.cvssv3BaseSeverity = cvssv3BaseSeverity;
    }

    /**
     * Get the value of CVSS3 Availability Impact.
     *
     * @return the value of CVSS3 Availability Impact
     */
    public String getCvssv3AvailabilityImpact() {
        return cvssv3AvailabilityImpact;
    }

    /**
     * Set the value of CVSS3 Availability Impact.
     *
     * @param cvssv3AvailabilityImpact new value of CVSS3 Availability Impact
     */
    public void setCvssv3AvailabilityImpact(String cvssv3AvailabilityImpact) {
        this.cvssv3AvailabilityImpact = cvssv3AvailabilityImpact;
    }

    /**
     * Get the value of CVSS3 Integrity Impact.
     *
     * @return the value of CVSS3 Integrity Impact
     */
    public String getCvssv3IntegrityImpact() {
        return cvssv3IntegrityImpact;
    }

    /**
     * Set the value of CVSS3 Integrity Impact.
     *
     * @param cvssv3IntegrityImpact new value of CVSS3 Integrity Impact
     */
    public void setCvssv3IntegrityImpact(String cvssv3IntegrityImpact) {
        this.cvssv3IntegrityImpact = cvssv3IntegrityImpact;
    }

    /**
     * Get the value of CVSS3 Confidentiality Impact.
     *
     * @return the value of CVSS3 Confidentiality Impact
     */
    public String getCvssv3ConfidentialityImpact() {
        return cvssv3ConfidentialityImpact;
    }

    /**
     * Set the value of CVSS3 Confidentiality Impact.
     *
     * @param cvssv3ConfidentialityImpact new value of CVSS3 Confidentiality
     * Impact
     */
    public void setCvssv3ConfidentialityImpact(String cvssv3ConfidentialityImpact) {
        this.cvssv3ConfidentialityImpact = cvssv3ConfidentialityImpact;
    }

    /**
     * Get the value of CVSS3 Scope.
     *
     * @return the value of CVSS3 Scope
     */
    public String getCvssv3Scope() {
        return cvssv3Scope;
    }

    /**
     * Set the value of CVSS3 Scope.
     *
     * @param cvssv3Scope new value of CVSS3 Scope
     */
    public void setCvssv3Scope(String cvssv3Scope) {
        this.cvssv3Scope = cvssv3Scope;
    }

    /**
     * Get the value of CVSS3 User Interaction.
     *
     * @return the value of CVSS3 User Interaction
     */
    public String getCvssv3UserInteraction() {
        return cvssv3UserInteraction;
    }

    /**
     * Set the value of CVSS3 User Interaction.
     *
     * @param cvssv3UserInteraction new value of CVSS3 User Interaction
     */
    public void setCvssv3UserInteraction(String cvssv3UserInteraction) {
        this.cvssv3UserInteraction = cvssv3UserInteraction;
    }

    /**
     * Get the value of CVSS3 Privileges Required.
     *
     * @return the value of CVSS3 Privileges Required
     */
    public String getCvssv3PrivilegesRequired() {
        return cvssv3PrivilegesRequired;
    }

    /**
     * Set the value of CVSS3 Privileges Required.
     *
     * @param cvssv3PrivilegesRequired new value of CVSS3 Privileges Required
     */
    public void setCvssv3PrivilegesRequired(String cvssv3PrivilegesRequired) {
        this.cvssv3PrivilegesRequired = cvssv3PrivilegesRequired;
    }

    /**
     * Get the value of CVSS3 Attack Complexity.
     *
     * @return the value of CVSS3 Attack Complexity
     */
    public String getCvssv3AttackComplexity() {
        return cvssv3AttackComplexity;
    }

    /**
     * Set the value of CVSS3 Attack Complexity.
     *
     * @param cvssv3AttackComplexity new value of CVSS3 Attack Complexity
     */
    public void setCvssv3AttackComplexity(String cvssv3AttackComplexity) {
        this.cvssv3AttackComplexity = cvssv3AttackComplexity;
    }

    /**
     * Get the value of CVSS3 Attack Vector.
     *
     * @return the value of CVSS3 Attack Vector
     */
    public String getCvssv3AttackVector() {
        return cvssv3AttackVector;
    }

    /**
     * Set the value of CVSS3 Attack Vector.
     *
     * @param cvssv3AttackVector new value of CVSS3 Attack Vector
     */
    public void setCvssv3AttackVector(String cvssv3AttackVector) {
        this.cvssv3AttackVector = cvssv3AttackVector;
    }

    /**
     * Get the value of CVSS3 Base Score.
     *
     * @return the value of CVSS3 Base Score
     */
    public String getCvssv3BaseScore() {
        return cvssv3BaseScore;
    }

    /**
     * Set the value of CVSS3 Base Score.
     *
     * @param cvssv3BaseScore new value of CVSS3 Base Score
     */
    public void setCvssv3BaseScore(String cvssv3BaseScore) {
        this.cvssv3BaseScore = cvssv3BaseScore;
    }

    /**
     * Get the value of CVSS2 Impact Score.
     *
     * @return the value of CVSS2 Impact Score
     */
    public String getCvssv2ImpactScore() {
        return cvssv2ImpactScore;
    }

    /**
     * Set the value of CVSS2 Impact Score.
     *
     * @param cvssv2ImpactScore new value of CVSS2 Impact Score
     */
    public void setCvssv2ImpactScore(String cvssv2ImpactScore) {
        this.cvssv2ImpactScore = cvssv2ImpactScore;
    }

    /**
     * Get the value of CVSS2 Exploitability Score.
     *
     * @return the value of CVSS2 Exploitability Score
     */
    public String getCvssv2ExploitabilityScore() {
        return cvssv2ExploitabilityScore;
    }

    /**
     * Set the value of CVSS2 Exploitability Score.
     *
     * @param cvssv2ExploitabilityScore new value of CVSS2 Exploitability Score
     */
    public void setCvssv2ExploitabilityScore(String cvssv2ExploitabilityScore) {
        this.cvssv2ExploitabilityScore = cvssv2ExploitabilityScore;
    }

    /**
     * Get the value of CVSS2 Version.
     *
     * @return the value of CVSS2 Version
     */
    public String getCvssv2Version() {
        return cvssv2Version;
    }

    /**
     * Set the value of CVSS2 Version.
     *
     * @param cvssv2Version new value of CVSS2 Version
     */
    public void setCvssv2Version(String cvssv2Version) {
        this.cvssv2Version = cvssv2Version;
    }

    /**
     * Get the value of CVSS2 Severity.
     *
     * @return the value of CVSS2 Severity
     */
    public String getCvssv2Severity() {
        return cvssv2Severity;
    }

    /**
     * Set the value of CVSS2 Severity.
     *
     * @param cvssv2Severity new value of CVSS2 Severity
     */
    public void setCvssv2Severity(String cvssv2Severity) {
        this.cvssv2Severity = cvssv2Severity;
    }

    /**
     * Get the value of CVSS2 Availability Impact.
     *
     * @return the value of CVSS2 Availability Impact
     */
    public String getCvssv2AvailabilityImpact() {
        return cvssv2AvailabilityImpact;
    }

    /**
     * Set the value of CVSS2 Availability Impact.
     *
     * @param cvssv2AvailabilityImpact new value of CVSS2 Availability Impact
     */
    public void setCvssv2AvailabilityImpact(String cvssv2AvailabilityImpact) {
        this.cvssv2AvailabilityImpact = cvssv2AvailabilityImpact;
    }

    /**
     * Get the value of CVSS2 Integrity Impact.
     *
     * @return the value of CVSS2 Integrity Impact
     */
    public String getCvssv2IntegrityImpact() {
        return cvssv2IntegrityImpact;
    }

    /**
     * Set the value of CVSS2 Integrity Impact.
     *
     * @param cvssv2IntegrityImpact new value of CVSS2 Integrity Impact
     */
    public void setCvssv2IntegrityImpact(String cvssv2IntegrityImpact) {
        this.cvssv2IntegrityImpact = cvssv2IntegrityImpact;
    }

    /**
     * Get the value of CVSS2 Confidentiality Impact.
     *
     * @return the value of CVSS2 Confidentiality Impact
     */
    public String getCvssv2ConfidentialityImpact() {
        return cvssv2ConfidentialityImpact;
    }

    /**
     * Set the value of CVSS2 Confidentiality Impact.
     *
     * @param cvssv2ConfidentialityImpact new value of CVSS2 Confidentiality Impact
     */
    public void setCvssv2ConfidentialityImpact(String cvssv2ConfidentialityImpact) {
        this.cvssv2ConfidentialityImpact = cvssv2ConfidentialityImpact;
    }

    /**
     * Get the value of CVSS2 Authentication.
     *
     * @return the value of CVSS2 Authentication
     */
    public String getCvssv2Authentication() {
        return cvssv2Authentication;
    }

    /**
     * Set the value of CVSS2 Authentication.
     *
     * @param cvssv2Authentication new value of CVSS2 Authentication
     */
    public void setCvssv2Authentication(String cvssv2Authentication) {
        this.cvssv2Authentication = cvssv2Authentication;
    }

    /**
     * Get the value of CVSS2 Access Complexity.
     *
     * @return the value of CVSS2 Access Complexity
     */
    public String getCvssv2AccessComplexity() {
        return cvssv2AccessComplexity;
    }

    /**
     * Set the value of CVSS2 Access Complexity.
     *
     * @param cvssv2AccessComplexity new value of CVSS2 Access Complexity
     */
    public void setCvssv2AccessComplexity(String cvssv2AccessComplexity) {
        this.cvssv2AccessComplexity = cvssv2AccessComplexity;
    }

    /**
     * Get the value of CVSS2 Access Vector.
     *
     * @return the value of CVSS2 Access Vector
     */
    public String getCvssv2AccessVector() {
        return cvssv2AccessVector;
    }

    /**
     * Set the value of CVSS2 Access Vector.
     *
     * @param cvssv2AccessVector new value of CVSS2 Access Vector
     */
    public void setCvssv2AccessVector(String cvssv2AccessVector) {
        this.cvssv2AccessVector = cvssv2AccessVector;
    }

    /**
     * Get the value of CVSS2 Score.
     *
     * @return the value of CVSS2 Score
     */
    public String getCvssv2Score() {
        return cvssv2Score;
    }

    /**
     * Set the value of CVSS2 Score.
     *
     * @param cvssv2Score new value of CVSS2 Score
     */
    public void setCvssv2Score(String cvssv2Score) {
        this.cvssv2Score = cvssv2Score;
    }

    /**
     * Get the name.
     *
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * Set the name.
     *
     * @param name the name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get the full description.
     *
     * @return the value of full description
     */
    public String getFullDescription() {
        return fullDescription;
    }

    /**
     * Set the full description.
     *
     * @param fullDescription the full description
     */
    public void setFullDescription(String fullDescription) {
        this.fullDescription = fullDescription;
    }

    /**
     * Get the short description.
     *
     * @return the short description
     */
    public String getShortDescription() {
        return shortDescription;
    }

    /**
     * Set the short description.
     *
     * @param shortDescription the short description
     */
    public void setShortDescription(String shortDescription) {
        this.shortDescription = shortDescription;
    }

    /**
     * Get the value of id.
     *
     * @return the value of id
     */
    public String getId() {
        return id;
    }

    /**
     * Set the value of id.
     *
     * @param id new value of id
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Get the value of CVSS4 Base Score.
     *
     * @return the value of CVSS4 Base Score
     */
    public String getCvssv4BaseScore() {
        return cvssv4BaseScore;
    }

    /**
     * Set the value of CVSS4 Base Score.
     * @param cvssv4BaseScore new value of CVSS4 Base Score
     */
    public void setCvssv4BaseScore(String cvssv4BaseScore) {
        this.cvssv4BaseScore = cvssv4BaseScore;
    }

    /**
     * Get the Cvssv4 Vector.
     * @return the Cvssv4 Vector
     */
    public String getCvssv4Vector() {
        return cvssv4Vector;
    }

    /**
     * Set the Cvssv4 Vector.
     * @param cvssv4Vector new value of Cvssv4 Vector
     */
    public void setCvssv4Vector(String cvssv4Vector) {
        this.cvssv4Vector = cvssv4Vector;
    }
}
