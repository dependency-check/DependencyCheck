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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;

import com.google.common.base.Strings;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import org.h2.tools.SimpleResultSet;

/**
 * Stored procedures for the H2 database.
 *
 * @author Jeremy Long
 */
public final class H2Functions {

    private H2Functions() {
        //empty constructor for utility class
    }

    //CSOFF: ParameterNumber
    /**
     * Adds a CPE to a vulnerability; if the CPE is not contained in the
     * database it is first added.
     *
     * @param conn the database connection
     * @param vulnerabilityId the vulnerability id
     * @param part the CPE part
     * @param vendor the CPE vendor
     * @param product the CPE product
     * @param version the CPE version
     * @param update the CPE update version
     * @param edition the CPE edition
     * @param language the CPE language
     * @param swEdition the CPE software edition
     * @param targetSw the CPE target software
     * @param targetHw the CPE target hardware
     * @param other the CPE other
     * @param ecosystem the ecosystem
     * @param versionEndExcluding a version range to identify the software
     * @param versionEndIncluding a version range to identify the software
     * @param versionStartExcluding a version range to identify the software
     * @param versionStartIncluding a version range to identify the software
     * @param vulnerable a flag indicating whether or not the software is
     * vulnerable
     * @throws SQLException thrown if there is an error adding the CPE or
     * software reference
     */
    public static void insertSoftware(final Connection conn, int vulnerabilityId, String part, String vendor,
            String product, String version, String update, String edition, String language, String swEdition,
            String targetSw, String targetHw, String other, String ecosystem, String versionEndExcluding,
            String versionEndIncluding, String versionStartExcluding, String versionStartIncluding, Boolean vulnerable) throws SQLException {
        int cpeID = 0;
        try (PreparedStatement selectCpeId = conn.prepareStatement("SELECT id, ecosystem FROM cpeEntry WHERE part=? AND vendor=? AND product=? "
                + "AND version=? AND update_version=? AND edition=? AND lang=? AND sw_edition=? AND target_sw=? AND target_hw=? AND other=?")) {
            selectCpeId.setString(1, part);
            selectCpeId.setString(2, vendor);
            selectCpeId.setString(3, product);
            selectCpeId.setString(4, version);
            selectCpeId.setString(5, update);
            selectCpeId.setString(6, edition);
            selectCpeId.setString(7, language);
            selectCpeId.setString(8, swEdition);
            selectCpeId.setString(9, targetSw);
            selectCpeId.setString(10, targetHw);
            selectCpeId.setString(11, other);

            try (ResultSet rs = selectCpeId.executeQuery()) {
                if (rs.next()) {
                    cpeID = rs.getInt(1);
                    final String e = rs.getString(2);
                    if (e == null && ecosystem != null) {
                        try (PreparedStatement updateEcosystem = conn.prepareStatement("UPDATE cpeEntry SET ecosystem=? WHERE id=?")) {
                            updateEcosystem.setString(1, ecosystem);
                            updateEcosystem.setInt(2, cpeID);
                            updateEcosystem.execute();
                        }
                    }
                }
            }
        }
        if (cpeID == 0) {
            final String[] returnedColumns = {"id"};
            try (PreparedStatement insertCpe = conn.prepareStatement("INSERT INTO cpeEntry (part, vendor, product, version, update_version, "
                    + "edition, lang, sw_edition, target_sw, target_hw, other, ecosystem) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    returnedColumns)) {
                insertCpe.setString(1, part);
                insertCpe.setString(2, vendor);
                insertCpe.setString(3, product);
                insertCpe.setString(4, version);
                insertCpe.setString(5, update);
                insertCpe.setString(6, edition);
                insertCpe.setString(7, language);
                insertCpe.setString(8, swEdition);
                insertCpe.setString(9, targetSw);
                insertCpe.setString(10, targetHw);
                insertCpe.setString(11, other);
                setStringOrNull(insertCpe, 12, ecosystem);
                insertCpe.executeUpdate();
                try (ResultSet rs = insertCpe.getGeneratedKeys()) {
                    if (rs.next()) {
                        cpeID = rs.getInt(1);
                    }
                }
            }
        }
        //CSON: ParameterNumber

        try (PreparedStatement insertSoftware = conn.prepareStatement("INSERT INTO software (cveid, cpeEntryId, "
                + "versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding, "
                + "vulnerable) VALUES (?, ?, ?, ?, ?, ?, ?)")) {
            insertSoftware.setInt(1, vulnerabilityId);
            insertSoftware.setInt(2, cpeID);

            setStringOrNull(insertSoftware, 3, versionEndExcluding);
            setStringOrNull(insertSoftware, 4, versionEndIncluding);
            setStringOrNull(insertSoftware, 5, versionStartExcluding);
            setStringOrNull(insertSoftware, 6, versionStartIncluding);
            setBooleanOrNull(insertSoftware, 7, vulnerable);
            insertSoftware.execute();
        }
    }

    //CSOFF: ParameterNumber
    /**
     * Updates or inserts the vulnerability into the database. If updating a
     * vulnerability the method will delete all software, CWE, and references
     * and new entries will be added later.
     *
     * @param conn the database connection
     * @param cve the CVE identifier
     * @param description the vulnerability description
     * @param v2Severity the CVSS v2 severity
     * @param v2ExploitabilityScore the CVSS v2 exploitability score
     * @param v2ImpactScore the CVSS v2 impact score
     * @param v2AcInsufInfo the CVSS v2 AcInsufInfo
     * @param v2ObtainAllPrivilege the CVSS v2 obtain all privilege flag
     * @param v2ObtainUserPrivilege the CVSS v2 obtain user privilege flag
     * @param v2ObtainOtherPrivilege the CVSS v2 obtain other privilege flag
     * @param v2UserInteractionRequired the CVSS v2 user interaction required
     * flag
     * @param v2Score the CVSS v2 score
     * @param v2AccessVector the CVSS v2 access vector
     * @param v2AccessComplexity the CVSS v2 access complexity
     * @param v2Authentication the CVSS v2 authentication
     * @param v2ConfidentialityImpact the CVSS v2 confidentiality impact
     * @param v2IntegrityImpact the CVSS v2 integrity impact
     * @param v2AvailabilityImpact the CVSS v2 availability impact
     * @param v2Version the CVSS v2 version
     * @param v3ExploitabilityScore the CVSS v3 exploitability score
     * @param v3ImpactScore the CVSS v3 impact score
     * @param v3AttackVector the CVSS v3 attack vector
     * @param v3AttackComplexity the CVSS v3 attack complexity
     * @param v3PrivilegesRequired the CVSS v3 privilege required flag
     * @param v3UserInteraction the CVSS v3 user interaction required flag
     * @param v3Scope the CVSS v3 scope
     * @param v3ConfidentialityImpact the CVSS v3 confidentiality impact
     * @param v3IntegrityImpact the CVSS v3 integrity impact
     * @param v3AvailabilityImpact the CVSS v3 availability impact
     * @param v3BaseScore the CVSS v3 base score
     * @param v3BaseSeverity the CVSS v3 base severity
     * @param v3Version the CVSS v3 version
     * @param v4version CVSS v4 data
     * @param v4attackVector CVSS v4 data
     * @param v4attackComplexity CVSS v4 data
     * @param v4attackRequirements CVSS v4 data
     * @param v4privilegesRequired CVSS v4 data
     * @param v4userInteraction CVSS v4 data
     * @param v4vulnConfidentialityImpact CVSS v4 data
     * @param v4vulnIntegrityImpact CVSS v4 data
     * @param v4vulnAvailabilityImpact CVSS v4 data
     * @param v4subConfidentialityImpact CVSS v4 data
     * @param v4subIntegrityImpact CVSS v4 data
     * @param v4subAvailabilityImpact CVSS v4 data
     * @param v4exploitMaturity CVSS v4 data
     * @param v4confidentialityRequirement CVSS v4 data
     * @param v4integrityRequirement CVSS v4 data
     * @param v4availabilityRequirement CVSS v4 data
     * @param v4modifiedAttackVector CVSS v4 data
     * @param v4modifiedAttackComplexity CVSS v4 data
     * @param v4modifiedAttackRequirements CVSS v4 data
     * @param v4modifiedPrivilegesRequired CVSS v4 data
     * @param v4modifiedUserInteraction CVSS v4 data
     * @param v4modifiedVulnConfidentialityImpact CVSS v4 data
     * @param v4modifiedVulnIntegrityImpact CVSS v4 data
     * @param v4modifiedVulnAvailabilityImpact CVSS v4 data
     * @param v4modifiedSubConfidentialityImpact CVSS v4 data
     * @param v4modifiedSubIntegrityImpact CVSS v4 data
     * @param v4modifiedSubAvailabilityImpact CVSS v4 data
     * @param v4safety CVSS v4 data
     * @param v4automatable CVSS v4 data
     * @param v4recovery CVSS v4 data
     * @param v4valueDensity CVSS v4 data
     * @param v4vulnerabilityResponseEffort CVSS v4 data
     * @param v4providerUrgency CVSS v4 data
     * @param v4baseScore CVSS v4 data
     * @param v4baseSeverity CVSS v4 data
     * @param v4threatScore CVSS v4 data
     * @param v4threatSeverity CVSS v4 data
     * @param v4environmentalScore CVSS v4 data
     * @param v4environmentalSeverity CVSS v4 data
     * @param v4source CVSS v4 data
     * @param v4type CVSS v4 data
     * @return a result set containing the vulnerability id
     * @throws SQLException thrown if there is an error updating or inserting
     * the vulnerability
     */
    public static ResultSet updateVulnerability(final Connection conn, String cve,
            String description, String v2Severity, Float v2ExploitabilityScore,
            Float v2ImpactScore, Boolean v2AcInsufInfo, Boolean v2ObtainAllPrivilege,
            Boolean v2ObtainUserPrivilege, Boolean v2ObtainOtherPrivilege, Boolean v2UserInteractionRequired,
            Float v2Score, String v2AccessVector, String v2AccessComplexity,
            String v2Authentication, String v2ConfidentialityImpact, String v2IntegrityImpact,
            String v2AvailabilityImpact, String v2Version, Float v3ExploitabilityScore,
            Float v3ImpactScore, String v3AttackVector, String v3AttackComplexity,
            String v3PrivilegesRequired, String v3UserInteraction, String v3Scope,
            String v3ConfidentialityImpact, String v3IntegrityImpact, String v3AvailabilityImpact,
            Float v3BaseScore, String v3BaseSeverity, String v3Version, String v4version,
            String v4attackVector, String v4attackComplexity, String v4attackRequirements,
            String v4privilegesRequired, String v4userInteraction, String v4vulnConfidentialityImpact,
            String v4vulnIntegrityImpact, String v4vulnAvailabilityImpact, String v4subConfidentialityImpact,
            String v4subIntegrityImpact, String v4subAvailabilityImpact, String v4exploitMaturity,
            String v4confidentialityRequirement, String v4integrityRequirement, String v4availabilityRequirement,
            String v4modifiedAttackVector, String v4modifiedAttackComplexity, String v4modifiedAttackRequirements,
            String v4modifiedPrivilegesRequired, String v4modifiedUserInteraction, String v4modifiedVulnConfidentialityImpact,
            String v4modifiedVulnIntegrityImpact, String v4modifiedVulnAvailabilityImpact, String v4modifiedSubConfidentialityImpact,
            String v4modifiedSubIntegrityImpact, String v4modifiedSubAvailabilityImpact, String v4safety,
            String v4automatable, String v4recovery, String v4valueDensity, String v4vulnerabilityResponseEffort,
            String v4providerUrgency, Float v4baseScore, String v4baseSeverity, Float v4threatScore,
            String v4threatSeverity, Float v4environmentalScore, String v4environmentalSeverity,
            String v4source, String v4type) throws SQLException {

        final SimpleResultSet ret = new SimpleResultSet();
        ret.addColumn("id", Types.INTEGER, 10, 0);
        final String url = conn.getMetaData().getURL();
        if ("jdbc:columnlist:connection".equals(url)) {
            // Virtual Table Functions get called multiple times by H2
            // JDBC URL jdbc:columnlist:connection indicates that H2 only wants to discover
            // the metadata (list of result columns) of the result and is not interested in the actual
            // execution of the function, so we should exit early with an empty resultset.
            return ret;
        }

        int vulnerabilityId = 0;
        try (PreparedStatement selectVulnerabilityId = conn.prepareStatement("SELECT id FROM VULNERABILITY CVE WHERE cve=?")) {
            selectVulnerabilityId.setString(1, cve);
            try (ResultSet rs = selectVulnerabilityId.executeQuery()) {
                if (rs.next()) {
                    vulnerabilityId = rs.getInt(1);
                }
            }
        }
        PreparedStatement merge = null;
        try {
            if (vulnerabilityId > 0) {
                //do deletes and updates
                try (PreparedStatement refs = conn.prepareStatement("DELETE FROM reference WHERE cveid = ?")) {
                    refs.setInt(1, vulnerabilityId);
                    refs.executeUpdate();
                }
                try (PreparedStatement software = conn.prepareStatement("DELETE FROM software WHERE cveid = ?")) {
                    software.setInt(1, vulnerabilityId);
                    software.executeUpdate();
                }
                try (PreparedStatement cwe = conn.prepareStatement("DELETE FROM cweEntry WHERE cveid = ?")) {
                    cwe.setInt(1, vulnerabilityId);
                    cwe.executeUpdate();
                }
                merge = conn.prepareStatement("UPDATE VULNERABILITY SET description=?, "
                        + "v2Severity=?, v2ExploitabilityScore=?, "
                        + "v2ImpactScore=?, v2AcInsufInfo=?, v2ObtainAllPrivilege=?, "
                        + "v2ObtainUserPrivilege=?, v2ObtainOtherPrivilege=?, v2UserInteractionRequired=?, "
                        + "v2Score=?, v2AccessVector=?, v2AccessComplexity=?, "
                        + "v2Authentication=?, v2ConfidentialityImpact=?, v2IntegrityImpact=?, "
                        + "v2AvailabilityImpact=?, v2Version=?, v3ExploitabilityScore=?, "
                        + "v3ImpactScore=?, v3AttackVector=?, v3AttackComplexity=?, "
                        + "v3PrivilegesRequired=?, v3UserInteraction=?, v3Scope=?, "
                        + "v3ConfidentialityImpact=?, v3IntegrityImpact=?, v3AvailabilityImpact=?, "
                        + "v3BaseScore=?, v3BaseSeverity=?, v3Version=?, v4version=?, v4attackVector=?, "
                        + "v4attackComplexity=?, v4attackRequirements=?, v4privilegesRequired=?, "
                        + "v4userInteraction=?, v4vulnConfidentialityImpact=?, v4vulnIntegrityImpact=?, "
                        + "v4vulnAvailabilityImpact=?, v4subConfidentialityImpact=?, v4subIntegrityImpact=?, "
                        + "v4subAvailabilityImpact=?, v4exploitMaturity=?, "
                        + "v4confidentialityRequirement=?, v4integrityRequirement=?, "
                        + "v4availabilityRequirement=?, v4modifiedAttackVector=?, "
                        + "v4modifiedAttackComplexity=?, v4modifiedAttackRequirements=?, "
                        + "v4modifiedPrivilegesRequired=?, v4modifiedUserInteraction=?, "
                        + "v4modifiedVulnConfidentialityImpact=?, v4modifiedVulnIntegrityImpact=?, "
                        + "v4modifiedVulnAvailabilityImpact=?, v4modifiedSubConfidentialityImpact=?, "
                        + "v4modifiedSubIntegrityImpact=?, v4modifiedSubAvailabilityImpact=?, "
                        + "v4safety=?, v4automatable=?, v4recovery=?, v4valueDensity=?, "
                        + "v4vulnerabilityResponseEffort=?, v4providerUrgency=?, v4baseScore=?, "
                        + "v4baseSeverity=?, v4threatScore=?, v4threatSeverity=?, v4environmentalScore=?, "
                        + "v4environmentalSeverity=?, v4source=?, v4type=?"
                        + "WHERE id=?");
            } else {
                //just do insert
                final String[] returnedColumns = {"id"};
                merge = conn.prepareStatement("INSERT INTO VULNERABILITY (description, "
                        + "v2Severity, v2ExploitabilityScore, "
                        + "v2ImpactScore, v2AcInsufInfo, v2ObtainAllPrivilege, "
                        + "v2ObtainUserPrivilege, v2ObtainOtherPrivilege, v2UserInteractionRequired, "
                        + "v2Score, v2AccessVector, v2AccessComplexity, "
                        + "v2Authentication, v2ConfidentialityImpact, v2IntegrityImpact, "
                        + "v2AvailabilityImpact, v2Version, v3ExploitabilityScore, "
                        + "v3ImpactScore, v3AttackVector, v3AttackComplexity, "
                        + "v3PrivilegesRequired, v3UserInteraction, v3Scope, "
                        + "v3ConfidentialityImpact, v3IntegrityImpact, v3AvailabilityImpact, "
                        + "v3BaseScore, v3BaseSeverity, v3Version, v4version, v4attackVector, "
                        + "v4attackComplexity, v4attackRequirements, v4privilegesRequired, "
                        + "v4userInteraction, v4vulnConfidentialityImpact, v4vulnIntegrityImpact, "
                        + "v4vulnAvailabilityImpact, v4subConfidentialityImpact, v4subIntegrityImpact, "
                        + "v4subAvailabilityImpact, v4exploitMaturity,v4confidentialityRequirement, "
                        + "v4integrityRequirement, v4availabilityRequirement,v4modifiedAttackVector, "
                        + "v4modifiedAttackComplexity, v4modifiedAttackRequirements,v4modifiedPrivilegesRequired, "
                        + "v4modifiedUserInteraction, v4modifiedVulnConfidentialityImpact,v4modifiedVulnIntegrityImpact, "
                        + "v4modifiedVulnAvailabilityImpact, v4modifiedSubConfidentialityImpact,v4modifiedSubIntegrityImpact, "
                        + "v4modifiedSubAvailabilityImpact, v4safety, v4automatable, v4recovery, v4valueDensity, "
                        + "v4vulnerabilityResponseEffort, v4providerUrgency, v4baseScore, v4baseSeverity, "
                        + "v4threatScore,v4threatSeverity, v4environmentalScore, v4environmentalSeverity, "
                        + "v4source, v4type, cve) VALUES (?, ?, ?, ?, ?, ?, "
                        + "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                        + "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                        + "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        returnedColumns);
            }

            merge.setString(1, description);

            setStringOrNull(merge, 2, v2Severity);
            setFloatOrNull(merge, 3, v2ExploitabilityScore);
            setFloatOrNull(merge, 4, v2ImpactScore);
            setBooleanOrNull(merge, 5, v2AcInsufInfo);
            setBooleanOrNull(merge, 6, v2ObtainAllPrivilege);
            setBooleanOrNull(merge, 7, v2ObtainUserPrivilege);
            setBooleanOrNull(merge, 8, v2ObtainOtherPrivilege);
            setBooleanOrNull(merge, 9, v2UserInteractionRequired);
            setFloatOrNull(merge, 10, v2Score);
            setStringOrNull(merge, 11, v2AccessVector);
            setStringOrNull(merge, 12, v2AccessComplexity);
            setStringOrNull(merge, 13, v2Authentication);
            setStringOrNull(merge, 14, v2ConfidentialityImpact);
            setStringOrNull(merge, 15, v2IntegrityImpact);
            setStringOrNull(merge, 16, v2AvailabilityImpact);
            setStringOrNull(merge, 17, v2Version);
            setFloatOrNull(merge, 18, v3ExploitabilityScore);
            setFloatOrNull(merge, 19, v3ImpactScore);
            setStringOrNull(merge, 20, v3AttackVector);
            setStringOrNull(merge, 21, v3AttackComplexity);
            setStringOrNull(merge, 22, v3PrivilegesRequired);
            setStringOrNull(merge, 23, v3UserInteraction);
            setStringOrNull(merge, 24, v3Scope);
            setStringOrNull(merge, 25, v3ConfidentialityImpact);
            setStringOrNull(merge, 26, v3IntegrityImpact);
            setStringOrNull(merge, 27, v3AvailabilityImpact);
            setFloatOrNull(merge, 28, v3BaseScore);
            setStringOrNull(merge, 29, v3BaseSeverity);
            setStringOrNull(merge, 30, v3Version);

            setStringOrNull(merge, 31, v4version);
            setStringOrNull(merge, 32, v4attackVector);
            setStringOrNull(merge, 33, v4attackComplexity);
            setStringOrNull(merge, 34, v4attackRequirements);
            setStringOrNull(merge, 35, v4privilegesRequired);
            setStringOrNull(merge, 36, v4userInteraction);
            setStringOrNull(merge, 37, v4vulnConfidentialityImpact);
            setStringOrNull(merge, 38, v4vulnIntegrityImpact);
            setStringOrNull(merge, 39, v4vulnAvailabilityImpact);
            setStringOrNull(merge, 40, v4subConfidentialityImpact);
            setStringOrNull(merge, 41, v4subIntegrityImpact);
            setStringOrNull(merge, 42, v4subAvailabilityImpact);
            setStringOrNull(merge, 43, v4exploitMaturity);
            setStringOrNull(merge, 44, v4confidentialityRequirement);
            setStringOrNull(merge, 45, v4integrityRequirement);
            setStringOrNull(merge, 46, v4availabilityRequirement);
            setStringOrNull(merge, 47, v4modifiedAttackVector);
            setStringOrNull(merge, 48, v4modifiedAttackComplexity);
            setStringOrNull(merge, 49, v4modifiedAttackRequirements);
            setStringOrNull(merge, 50, v4modifiedPrivilegesRequired);
            setStringOrNull(merge, 51, v4modifiedUserInteraction);
            setStringOrNull(merge, 52, v4modifiedVulnConfidentialityImpact);
            setStringOrNull(merge, 53, v4modifiedVulnIntegrityImpact);
            setStringOrNull(merge, 54, v4modifiedVulnAvailabilityImpact);
            setStringOrNull(merge, 55, v4modifiedSubConfidentialityImpact);
            setStringOrNull(merge, 56, v4modifiedSubIntegrityImpact);
            setStringOrNull(merge, 57, v4modifiedSubAvailabilityImpact);
            setStringOrNull(merge, 58, v4safety);
            setStringOrNull(merge, 59, v4automatable);
            setStringOrNull(merge, 60, v4recovery);
            setStringOrNull(merge, 61, v4valueDensity);
            setStringOrNull(merge, 62, v4vulnerabilityResponseEffort);
            setStringOrNull(merge, 63, v4providerUrgency);
            setFloatOrNull(merge, 64, v4baseScore);
            setStringOrNull(merge, 65, v4baseSeverity);
            setFloatOrNull(merge, 66, v4threatScore);
            setStringOrNull(merge, 67, v4threatSeverity);
            setFloatOrNull(merge, 68, v4environmentalScore);
            setStringOrNull(merge, 69, v4environmentalSeverity);
            setStringOrNull(merge, 70, v4source);
            setStringOrNull(merge, 71, v4type);

            //cve must be the last entry
            if (vulnerabilityId == 0) {
                merge.setString(72, cve);
            } else {
                merge.setInt(72, vulnerabilityId);
            }

            final int count = merge.executeUpdate();
            if (vulnerabilityId == 0) {
                try (ResultSet rs = merge.getGeneratedKeys()) {
                    if (rs.next()) {
                        vulnerabilityId = rs.getInt(1);
                    }
                }
            }
        } finally {
            if (merge != null) {
                merge.close();
            }
        }
        ret.addRow(vulnerabilityId);
        return ret;
    }
    //CSON: ParameterNumber

    //CSOFF: ParameterNumber
    /**
     * Update or insert a known exploited vulnerability.
     *
     * @param conn the connection
     * @param cveId the id
     * @param vendorProject the vendor/project
     * @param product the product
     * @param vulnerabilityName the vulnerability name
     * @param dateAdded the date added
     * @param shortDescription the short description
     * @param requiredAction the action required
     * @param dueDate the due date
     * @param notes notes
     * @throws SQLException thrown if there is a database error merging the
     * Known Exploited information to the database
     */
    public static void mergeKnownExploited(final Connection conn, String cveId,
            String vendorProject, String product, String vulnerabilityName,
            String dateAdded, String shortDescription, String requiredAction,
            String dueDate, String notes) throws SQLException {

        String id = "";
        try (PreparedStatement selectVulnerabilityId = conn.prepareStatement("SELECT cveID FROM knownExploited cveID WHERE cveID=?")) {
            selectVulnerabilityId.setString(1, cveId);
            try (ResultSet rs = selectVulnerabilityId.executeQuery()) {
                if (rs.next()) {
                    id = rs.getString(1);
                }
            }
        }
        PreparedStatement merge = null;
        try {
            if (Strings.isNullOrEmpty(id)) {
                merge = conn.prepareStatement("INSERT INTO knownExploited ("
                        + "vendorProject, product, vulnerabilityName, "
                        + "dateAdded, shortDescription, requiredAction, "
                        + "dueDate, notes, cveID) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
            } else {
                merge = conn.prepareStatement("UPDATE knownExploited SET "
                        + "vendorProject=?, product=?, vulnerabilityName=?, "
                        + "dateAdded=?, shortDescription=?, requiredAction=?, "
                        + "dueDate=?, notes=? WHERE cveID=?");
            }

            setStringOrNull(merge, 1, vendorProject);
            setStringOrNull(merge, 2, product);
            setStringOrNull(merge, 3, vulnerabilityName);
            setStringOrNull(merge, 4, dateAdded);
            setStringOrNull(merge, 5, shortDescription);
            setStringOrNull(merge, 6, requiredAction);
            setStringOrNull(merge, 7, dueDate);
            setStringOrNull(merge, 8, notes);
            setStringOrNull(merge, 9, cveId);
            merge.execute();
        } finally {
            if (merge != null) {
                merge.close();
            }
        }
    }
    //CSON: ParameterNumber

    /**
     * Sets a parameter value on a prepared statement with null checks.
     *
     * @param ps the prepared statement
     * @param i the parameter index
     * @param value the value
     * @throws SQLException thrown if there is an error setting the parameter
     */
    private static void setStringOrNull(PreparedStatement ps, int i, String value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.NULL);
        } else {
            ps.setString(i, value);
        }
    }

    /**
     * Sets a parameter value on a prepared statement with null checks.
     *
     * @param ps the prepared statement
     * @param i the parameter index
     * @param value the value
     * @throws SQLException thrown if there is an error setting the parameter
     */
    private static void setFloatOrNull(PreparedStatement ps, int i, Float value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.NULL);
        } else {
            ps.setFloat(i, value);
        }
    }

    /**
     * Sets a parameter value on a prepared statement with null checks.
     *
     * @param ps the prepared statement
     * @param i the parameter index
     * @param value the value
     * @throws SQLException thrown if there is an error setting the parameter
     */
    private static void setBooleanOrNull(PreparedStatement ps, int i, Boolean value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.NULL);
        } else {
            ps.setBoolean(i, value);
        }
    }
}
