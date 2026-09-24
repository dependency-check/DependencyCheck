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
 * Copyright (c) 2018 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;


import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;

import javax.annotation.concurrent.ThreadSafe;
import java.io.Serializable;
import java.util.List;

/**
 * The response from NPM Audit API will respond with 0 or more advisories. This
 * class defines the Advisory objects returned.
 *
 * @author Steve Springett
 */
@ThreadSafe
public class Advisory implements Serializable {

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = -6157232800626565475L;

    /**
     * The github_advisory_id of the advisory as issued by GHSA-hosted NPM Audit API.
     */
    private String ghsaId;

    /**
     * The timestamp of which the advisory was created.
     */
    private String created;

    /**
     * The timestamp of the last update to the advisory.
     */
    private String updated;

    /**
     * The title/name of the advisory.
     */
    private String title;

    /**
     * A detailed description of the advisory.
     */
    private String overview;

    /**
     * Recommendations for mitigation. Typically involves updating to a newer
     * release.
     */
    private String recommendation;

    /**
     * The name of the individual or organization that found the issue.
     */
    private String foundBy;

    /**
     * The name of the individual or organization that reported the issue.
     */
    private String reportedBy;

    /**
     * The name of the Node module the advisory is for.
     */
    private String moduleName;

    /**
     * The version of the Node module.
     */
    private String version;

    /**
     * The optional CVE(s) associated with this advisory.
     */
    private List<String> cves;

    /**
     * A string representation of the versions containing the vulnerability.
     */
    private String vulnerableVersions;

    /**
     * A string representation of the versions that have been patched.
     */
    private String patchedVersions;

    /**
     * The references names in the advisory. This field contains MarkDown
     * (including \n, *, and other characters)
     */
    private String references;

    /**
     * The access of the advisory.
     */
    private String access;

    /**
     * The severity of the advisory.
     */
    private String severity;

    /**
     * The CWEs of the advisory.
     */
    private List<String> cwes;

    /**
     * The CVSSv3 of the advisory.
     */
    private CvssV3 cvssV3;

    public String getCreated() {
        return created;
    }

    public void setCreated(String created) {
        this.created = created;
    }

    public String getUpdated() {
        return updated;
    }

    public void setUpdated(String updated) {
        this.updated = updated;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getOverview() {
        return overview;
    }

    public void setOverview(String overview) {
        this.overview = overview;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    public String getFoundBy() {
        return foundBy;
    }

    public void setFoundBy(String foundBy) {
        this.foundBy = foundBy;
    }

    public String getReportedBy() {
        return reportedBy;
    }

    public void setReportedBy(String reportedBy) {
        this.reportedBy = reportedBy;
    }

    public String getModuleName() {
        return moduleName;
    }

    public void setModuleName(String moduleName) {
        this.moduleName = moduleName;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public List<String> getCves() {
        return cves;
    }

    public void setCves(List<String> cves) {
        this.cves = cves;
    }

    public String getVulnerableVersions() {
        return vulnerableVersions;
    }

    public void setVulnerableVersions(String vulnerableVersions) {
        this.vulnerableVersions = vulnerableVersions;
    }

    public String getPatchedVersions() {
        return patchedVersions;
    }

    public void setPatchedVersions(String patchedVersions) {
        this.patchedVersions = patchedVersions;
    }

    public String getReferences() {
        return references;
    }

    public void setReferences(String references) {
        this.references = references;
    }

    public String getAccess() {
        return access;
    }

    public void setAccess(String access) {
        this.access = access;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public List<String> getCwes() {
        return cwes;
    }

    public void setCwes(List<String> cwes) {
        this.cwes = cwes;
    }

    /**
     * Extracts the GHSA identifier from a GitHub advisory URL such as
     * `https://github.com/advisories/GHSA-c9f4-xj24-8jqx`. Audit tooling
     * reports advisories with such URLs rather than a discrete GHSA
     * identifier.
     *
     * @param url the advisory URL
     * @return the GHSA identifier; or null if the URL does not reference a
     * GHSA
     */
    public static String ghsaIdFromUrl(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        final int lastSlashIndex = url.lastIndexOf('/');
        if (lastSlashIndex == -1 || lastSlashIndex == url.length() - 1) {
            return null;
        }
        final String id = url.substring(lastSlashIndex + 1);
        return id.startsWith("GHSA-") ? id : null;
    }

    public String getGhsaId() {
        return ghsaId;
    }

    public void setGhsaId(String ghsaId) {
        this.ghsaId = ghsaId;
    }

    public CvssV3 getCvssV3() {
        return cvssV3;
    }

    public void setCvssV3(CvssV3 cvssV3) {
        this.cvssV3 = cvssV3;
    }
}
