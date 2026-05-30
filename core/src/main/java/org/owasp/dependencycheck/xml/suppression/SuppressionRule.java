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

import org.apache.commons.lang3.Strings;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.jspecify.annotations.NonNull;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;

import javax.annotation.concurrent.NotThreadSafe;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class SuppressionRule {

    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SuppressionRule.class);
    /**
     * The file path for the suppression.
     */
    private PropertyType filePath;

    /**
     * The SHA1 hash.
     */
    private String sha1;
    /**
     * A list of CPEs to suppression
     */
    private List<PropertyType> cpe = new ArrayList<>();
    /**
     * The list of cvssBelow scores.
     */
    private List<Double> cvssBelow = new ArrayList<>();
    /**
     * The list of cvssV2Below scores.
     */
    private List<Double> cvssV2Below = new ArrayList<>();
    /**
     * The list of cvssV3Below scores.
     */
    private List<Double> cvssV3Below = new ArrayList<>();
    /**
     * The list of cvssV4Below scores.
     */
    private List<Double> cvssV4Below = new ArrayList<>();
    /**
     * The list of CWE entries to suppress.
     */
    private List<String> cwe = new ArrayList<>();
    /**
     * The list of CVE entries to suppress.
     */
    private List<String> cve = new ArrayList<>();
    /**
     * The list of vulnerability name entries to suppress.
     */
    private final List<PropertyType> vulnerabilityNames = new ArrayList<>();
    /**
     * A Maven GAV to suppression.
     */
    private PropertyType gav = null;
    /**
     * The list of vulnerability name entries to suppress.
     */
    private PropertyType packageUrl = null;
    /**
     * The notes added in suppression file
     */

    private String notes;

    /**
     * A flag indicating whether or not the suppression rule is a core/base rule
     * that should not be included in the resulting report in the "suppressed"
     * section.
     */
    private boolean base;

    /**
     * A date until which the suppression is to be retained. This can be used to
     * make a temporary suppression that auto-expires to suppress a CVE while
     * waiting for the vulnerability fix of the dependency to be released.
     */
    private Calendar until;

    /**
     * A flag whether or not the rule matched a dependency & CPE.
     */
    private boolean matched = false;

    /**
     * Get the value of matched.
     *
     * @return the value of matched
     */
    public boolean isMatched() {
        return matched;
    }

    /**
     * Set the value of matched.
     *
     * @param matched new value of matched
     */
    public void setMatched(boolean matched) {
        this.matched = matched;
    }

    /**
     * Get the (@code{nullable}) value of until.
     *
     * @return the value of until
     */
    public Calendar getUntil() {
        return until;
    }

    /**
     * Set the value of until.
     *
     * @param until new value of until
     */
    public void setUntil(Calendar until) {
        this.until = until;
    }

    /**
     * Get the value of filePath.
     *
     * @return the value of filePath
     */
    public PropertyType getFilePath() {
        return filePath;
    }

    /**
     * Set the value of filePath.
     *
     * @param filePath new value of filePath
     */
    public void setFilePath(PropertyType filePath) {
        this.filePath = filePath;
    }

    /**
     * Get the value of sha1.
     *
     * @return the value of sha1
     */
    public String getSha1() {
        return sha1;
    }

    /**
     * Set the value of SHA1.
     *
     * @param sha1 new value of SHA1
     */
    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    /**
     * Get the value of CPE.
     *
     * @return the value of CPE
     */
    public List<PropertyType> getCpe() {
        return cpe;
    }

    /**
     * Set the value of CPE.
     *
     * @param cpe new value of CPE
     */
    public void setCpe(List<PropertyType> cpe) {
        this.cpe = cpe;
    }

    /**
     * Adds the CPE to the CPE list.
     *
     * @param cpe the CPE to add
     */
    public void addCpe(PropertyType cpe) {
        this.cpe.add(cpe);
    }

    /**
     * Adds the CPE to the CPE list.
     *
     * @param name the vulnerability name to add
     */
    public void addVulnerabilityName(PropertyType name) {
        this.vulnerabilityNames.add(name);
    }

    /**
     * Returns whether or not this suppression rule as CPE entries.
     *
     * @return whether or not this suppression rule as CPE entries
     */
    public boolean hasCpe() {
        return !cpe.isEmpty();
    }

    /**
     * Get the value of cvssBelow.
     *
     * @return the value of cvssBelow
     */
    public List<Double> getCvssBelow() {
        return cvssBelow;
    }

    /**
     * Set the value of cvssBelow.
     *
     * @param cvssBelow new value of cvssBelow
     */
    public void setCvssBelow(List<Double> cvssBelow) {
        this.cvssBelow = cvssBelow;
    }

    /**
     * Adds the CVSS to the cvssBelow list.
     *
     * @param cvss the CVSS to add
     */
    public void addCvssBelow(Double cvss) {
        this.cvssBelow.add(cvss);
    }

    /**
     * Returns whether or not this suppression rule has CVSS suppression criteria.
     *
     * @return whether or not this suppression rule has CVSS suppression criteria.
     */
    public boolean hasCvssBelow() {
        return !cvssBelow.isEmpty();
    }

    /**
     * Get the value of cvssV2Below.
     *
     * @return the value of cvssV2Below
     */
    public List<Double> getCvssV2Below() {
        return cvssV2Below;
    }

    /**
     * Set the value of cvssV2Below.
     *
     * @param cvssV2Below new value of cvssV2Below
     */
    public void setCvssV2Below(List<Double> cvssV2Below) {
        this.cvssV2Below = cvssV2Below;
    }

    /**
     * Adds the CVSS to the cvssV2Below list.
     *
     * @param cvss the CVSS to add
     */
    public void addCvssV2Below(Double cvss) {
        this.cvssV2Below.add(cvss);
    }

    /**
     * Returns whether or not this suppression rule has CVSS v2 suppression criteria.
     *
     * @return whether or not this suppression rule has CVSS v2 suppression criteria.
     */
    public boolean hasCvssV2Below() {
        return !cvssV2Below.isEmpty();
    }

    /**
     * Get the value of cvssV3Below.
     *
     * @return the value of cvssV3Below
     */
    public List<Double> getCvssV3Below() {
        return cvssV3Below;
    }

    /**
     * Set the value of cvssV3Below.
     *
     * @param cvssV3Below new value of cvssV3Below
     */
    public void setCvssV3Below(List<Double> cvssV3Below) {
        this.cvssV3Below = cvssV3Below;
    }

    /**
     * Adds the CVSS to the cvssV3Below list.
     *
     * @param cvss the CVSS to add
     */
    public void addCvssV3Below(Double cvss) {
        this.cvssV3Below.add(cvss);
    }

    /**
     * Returns whether or not this suppression rule has CVSS v3 suppression criteria.
     *
     * @return whether or not this suppression rule has CVSS v3 suppression criteria.
     */
    public boolean hasCvssV3Below() {
        return !cvssV3Below.isEmpty();
    }

    /**
     * Get the value of cvssV4Below.
     *
     * @return the value of cvssV4Below
     */
    public List<Double> getCvssV4Below() {
        return cvssV4Below;
    }

    /**
     * Set the value of cvssV4Below.
     *
     * @param cvssV4Below new value of cvssV4Below
     */
    public void setCvssV4Below(List<Double> cvssV4Below) {
        this.cvssV4Below = cvssV4Below;
    }

    /**
     * Adds the CVSS to the cvssV4Below list.
     *
     * @param cvss the CVSS to add
     */
    public void addCvssV4Below(Double cvss) {
        this.cvssV4Below.add(cvss);
    }

    /**
     * Returns whether or not this suppression rule has CVSS v4 suppression criteria.
     *
     * @return whether or not this suppression rule has CVSS v4 suppression criteria.
     */
    public boolean hasCvssV4Below() {
        return !cvssV4Below.isEmpty();
    }

    /**
     * Get the value of notes.
     *
     * @return the value of notes
     */
    public String getNotes() {
        return notes;
    }

    /**
     * Set the value of notes.
     *
     * @param notes new value of notes
     */
    public void setNotes(String notes) {
        this.notes = notes;
    }

    /**
     * Returns whether this suppression rule has notes entries.
     *
     * @return whether this suppression rule has notes entries
     */
    public boolean hasNotes() {
        return !notes.isEmpty();
    }

    /**
     * Get the value of CWE.
     *
     * @return the value of CWE
     */
    public List<String> getCwe() {
        return cwe;
    }

    /**
     * Set the value of CWE.
     *
     * @param cwe new value of CWE
     */
    public void setCwe(List<String> cwe) {
        this.cwe = cwe;
    }

    /**
     * Adds the CWE to the CWE list.
     *
     * @param cwe the CWE to add
     */
    public void addCwe(String cwe) {
        this.cwe.add(cwe);
    }

    /**
     * Returns whether this suppression rule has CWE entries.
     *
     * @return whether this suppression rule has CWE entries
     */
    public boolean hasCwe() {
        return !cwe.isEmpty();
    }

    /**
     * Get the value of CVE.
     *
     * @return the value of CVE
     */
    public List<String> getCve() {
        return cve;
    }

    /**
     * Set the value of CVE.
     *
     * @param cve new value of CVE
     */
    public void setCve(List<String> cve) {
        this.cve = cve;
    }

    /**
     * Adds the CVE to the CVE list.
     *
     * @param cve the CVE to add
     */
    public void addCve(String cve) {
        this.cve.add(cve);
    }

    /**
     * Returns whether this suppression rule has CVE entries.
     *
     * @return whether this suppression rule has CVE entries
     */
    public boolean hasCve() {
        return !cve.isEmpty();
    }

    /**
     * Returns whether this suppression rule has vulnerabilityName entries.
     *
     * @return whether this suppression rule has vulnerabilityName entries
     */
    public boolean hasVulnerabilityName() {
        return !vulnerabilityNames.isEmpty();
    }

    /**
     * Get the value of Maven GAV.
     *
     * @return the value of GAV
     */
    public PropertyType getGav() {
        return gav;
    }

    /**
     * Set the value of Maven GAV.
     *
     * @param gav new value of Maven GAV
     */
    public void setGav(PropertyType gav) {
        this.gav = gav;
    }

    /**
     * Returns whether or not this suppression rule as GAV entries.
     *
     * @return whether or not this suppression rule as GAV entries
     */
    public boolean hasGav() {
        return gav != null;
    }

    /**
     * Set the value of Package URL.
     *
     * @param purl new value of package URL
     */
    public void setPackageUrl(PropertyType purl) {
        this.packageUrl = purl;
    }

    /**
     * Returns whether or not this suppression rule as packageUrl entries.
     *
     * @return whether or not this suppression rule as packageUrl entries
     */
    public boolean hasPackageUrl() {
        return packageUrl != null;
    }

    /**
     * Get the value of base.
     *
     * @return the value of base
     */
    public boolean isBase() {
        return base;
    }

    /**
     * Set the value of base.
     *
     * @param base new value of base
     */
    public void setBase(boolean base) {
        this.base = base;
    }

    /**
     * Processes a given dependency to determine if any CPE, CVE, CWE, or CVSS
     * scores should be suppressed. If any should be, they are removed from the
     * dependency.
     *
     * @param dependency a project dependency to analyze
     */
    public void process(Dependency dependency) {
        if (filePath != null && !filePath.matches(dependency.getFilePath())) {
            return;
        }
        if (sha1 != null && !sha1.equalsIgnoreCase(dependency.getSha1sum())) {
            return;
        }
        if (hasGav() && dependency.getSoftwareIdentifiers().stream()
                .noneMatch(i -> identifierMatches(this.gav, i))) {
            return;
        }
        if (hasPackageUrl() && dependency.getSoftwareIdentifiers().stream()
                .noneMatch(i -> purlMatches(this.packageUrl, i))) {
            return;
        }

        if (hasCpe()) {
            final Set<Identifier> removeIdentifiers = new HashSet<>();
            for (Identifier i : dependency.getVulnerableSoftwareIdentifiers()) {
                for (PropertyType c : this.cpe) {
                    if (identifierMatches(c, i)) {
                        if (!isBase()) {
                            matched = true;
                            if (this.notes != null) {
                                i.setNotes(this.notes);
                            }
                            dependency.addSuppressedIdentifier(i);
                        }
                        removeIdentifiers.add(i);
                        break;
                    }
                }
            }
            removeIdentifiers.forEach(dependency::removeVulnerableSoftwareIdentifier);
        }
        if (hasCve() || hasVulnerabilityName() || hasCwe() || hasCvssBelow() || hasCvssV2Below() || hasCvssV3Below() || hasCvssV4Below()) {
            final Set<Vulnerability> removeVulns = new HashSet<>();
            for (Vulnerability v : dependency.getVulnerabilities()) {
                boolean remove = false;
                for (String entry : this.cve) {
                    if (entry.equalsIgnoreCase(v.getName())) {
                        removeVulns.add(v);
                        remove = true;
                        break;
                    }
                }
                if (!remove && this.cwe != null && !v.getCwes().isEmpty()) {
                    for (String entry : this.cwe) {
                        final String toMatch = String.format("CWE-%s", entry);
                        if (v.getCwes().stream().anyMatch(toTest -> toMatch.regionMatches(0, toTest, 0, toMatch.length()))) {
                            remove = true;
                            removeVulns.add(v);
                            break;
                        }
                    }
                }
                if (!remove && v.getName() != null) {
                    for (PropertyType entry : this.vulnerabilityNames) {
                        if (entry.matches(v.getName())) {
                            remove = true;
                            removeVulns.add(v);
                            break;
                        }
                    }
                }
                if (!remove) {
                    if (suppressedBasedOnScore(v)) {
                        remove = true;
                        removeVulns.add(v);
                    }
                }
                if (remove && !isBase()) {
                    matched = true;
                    if (this.notes != null) {
                        v.setNotes(this.notes);
                    }
                    dependency.addSuppressedVulnerability(v);
                }
            }
            removeVulns.forEach(dependency::removeVulnerability);
        }
    }

    boolean suppressedBasedOnScore(Vulnerability v) {
        if (!cvssBelow.isEmpty()) {
            for (Double cvss : this.cvssBelow) {
                //TODO validate this comparison
                if (v.getCvssV2() != null && v.getCvssV2().getCvssData().getBaseScore().compareTo(cvss) < 0) {
                    return true;
                }
                if (v.getCvssV3() != null && v.getCvssV3().getCvssData().getBaseScore().compareTo(cvss) < 0) {
                    return true;
                }
                if (v.getCvssV4() != null && v.getCvssV4().getCvssData().getBaseScore().compareTo(cvss) < 0) {
                    return true;
                }
            }
            return false;
        }

        if (hasCvssV2Below() || hasCvssV3Below() || hasCvssV4Below()) {
            Double v2SuppressionThreshold = this.cvssV2Below.stream().max(Double::compare).orElse(11.0);
            Double v3SuppressionThreshold = this.cvssV3Below.stream().max(Double::compare).orElse(11.0);
            Double v4SuppressionThreshold = this.cvssV4Below.stream().max(Double::compare).orElse(11.0);

            Double v2Score = v.getCvssV2() != null ? v.getCvssV2().getCvssData().getBaseScore() : null;
            Double v3Score = v.getCvssV3() != null ? v.getCvssV3().getCvssData().getBaseScore() : null;
            Double v4Score = v.getCvssV4() != null ? v.getCvssV4().getCvssData().getBaseScore() : null;

            // only if all version indicate suppression will the vulnerability be suppressed
            // so if we are missing data (score or threshold) for a specific version we assume suppression
            boolean cvssV2CheckSuppressing = v2Score == null || v2Score < v2SuppressionThreshold;
            boolean cvssV3CheckSuppressing = v3Score == null || v3Score < v3SuppressionThreshold;
            boolean cvssV4CheckSuppressing = v4Score == null || v4Score < v4SuppressionThreshold;

            return cvssV2CheckSuppressing && cvssV3CheckSuppressing && cvssV4CheckSuppressing;
        }

        return false;
    }

    /**
     * Determines if the cpeEntry specified as a PropertyType matches the given
     * Identifier.
     *
     * @param suppressionEntry a suppression rule entry
     * @param identifier a CPE identifier to check
     * @return true if the entry matches; otherwise false
     */
    protected boolean purlMatches(PropertyType suppressionEntry, Identifier identifier) {
        if (identifier instanceof PurlIdentifier) {
            final PurlIdentifier purl = (PurlIdentifier) identifier;
            return suppressionEntry.matches(purl.toString());
        }
        return false;
    }

    /**
     * Determines if the cpeEntry specified as a PropertyType matches the given
     * Identifier.
     *
     * @param suppressionEntry a suppression rule entry
     * @param identifier a CPE identifier to check
     * @return true if the entry matches; otherwise false
     */
    protected boolean identifierMatches(PropertyType suppressionEntry, Identifier identifier) {
        if (identifier instanceof PurlIdentifier) {
            final PurlIdentifier purl = (PurlIdentifier) identifier;
            return suppressionEntry.matches(purl.toGav());
        } else if (identifier instanceof CpeIdentifier) {
            final Cpe cpe = ((CpeIdentifier) identifier).getCpe();
            try {
                // Override normal matching for non-regex CPE rules to be a prefix match rather than exact
                String cpe22Uri = cpe.toCpe22Uri();
                return suppressionEntry.isRegex() ? suppressionEntry.matches(cpe22Uri) : cpe22UriPrefixMatches(suppressionEntry, cpe22Uri);
            } catch (CpeEncodingException ex) {
                LOGGER.debug("Unable to convert CPE [{}] to 22 URI due to [{}], will try direct string match to rule.", cpe, ex.toString());
            }
        }
        // Fallback and GenericIdentifier (?)
        return suppressionEntry.matches(identifier.getValue());
    }

    private static boolean cpe22UriPrefixMatches(PropertyType suppressionEntry, String cpe22Uri) {
        String candidate = cpe22Uri + cpePartMatchingSuffixFor(suppressionEntry);
        return (suppressionEntry.isCaseSensitive() ? Strings.CS : Strings.CI)
                .startsWith(candidate, suppressionEntry.getValue());
    }

    /**
     * Uses the passed rule to determine whether the match should be strict; i.e whether the match must be a prefix of
     * the CPE 2.2 URI, but a whole part; rather than matching part way through.
     * Prefix-matching rules ending with the CPE colon delimiter imply a strict match is necessary.
     *
     * @param rule A non-regex CPE prefix-matching rule
     * @return A suffix for simple string matching of a CPE 2.2 URI
     */
    private static @NonNull String cpePartMatchingSuffixFor(PropertyType rule) {
        return rule.getValue().endsWith(":") ? ":" : "";
    }

    /**
     * Standard toString implementation.
     *
     * @return a string representation of this object
     */
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder(64);
        sb.append("SuppressionRule{");
        if (until != null) {
            final String dt = DateFormatUtils.ISO_8601_EXTENDED_DATETIME_TIME_ZONE_FORMAT.format(until);
            sb.append("until=").append(dt).append(',');
        }
        if (filePath != null) {
            sb.append("filePath=").append(filePath).append(',');
        }
        if (sha1 != null) {
            sb.append("sha1=").append(sha1).append(',');
        }
        if (packageUrl != null) {
            sb.append("packageUrl=").append(packageUrl).append(',');
        }
        if (gav != null) {
            sb.append("gav=").append(gav).append(',');
        }
        if (cpe != null && !cpe.isEmpty()) {
            sb.append("cpe={");
            cpe.forEach((pt) -> sb.append(pt).append(','));
            sb.append('}');
        }
        if (cwe != null && !cwe.isEmpty()) {
            sb.append("cwe={");
            cwe.forEach((s) -> sb.append(s).append(','));
            sb.append('}');
        }
        if (cve != null && !cve.isEmpty()) {
            sb.append("cve={");
            cve.forEach((s) -> sb.append(s).append(','));
            sb.append('}');
        }
        if (vulnerabilityNames != null && !vulnerabilityNames.isEmpty()) {
            sb.append("vulnerabilityName={");
            vulnerabilityNames.forEach((pt) -> sb.append(pt).append(','));
            sb.append('}');
        }
        if (cvssBelow != null && !cvssBelow.isEmpty()) {
            sb.append("cvssBelow={");
            cvssBelow.forEach((s) -> sb.append(s).append(','));
            sb.append('}');
        }
        if (cvssV2Below != null && !cvssV2Below.isEmpty()) {
            sb.append("cvssV2Below={");
            cvssV2Below.forEach((s) -> sb.append(s).append(','));
            sb.append('}');
        }
        if (cvssV3Below != null && !cvssV3Below.isEmpty()) {
            sb.append("cvssV3Below={");
            cvssV3Below.forEach((s) -> sb.append(s).append(','));
            sb.append('}');
        }
        if (cvssV4Below != null && !cvssV4Below.isEmpty()) {
            sb.append("cvssV4Below={");
            cvssV4Below.forEach((s) -> sb.append(s).append(','));
            sb.append('}');
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Suppression rules are considered equal if all properties except the "notes" and mutual "matched"
     * status are equal.
     *
     * @param o   the reference object with which to compare.
     * @return whether the object is equals to this one
     */
    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        if (this == o) return true;
        SuppressionRule that = (SuppressionRule) o;
        return base == that.base
                && Objects.equals(filePath, that.filePath)
                && Objects.equals(sha1, that.sha1)
                && Objects.equals(cpe, that.cpe)
                && Objects.equals(cvssBelow, that.cvssBelow)
                && Objects.equals(cvssV2Below, that.cvssV2Below)
                && Objects.equals(cvssV3Below, that.cvssV3Below)
                && Objects.equals(cvssV4Below, that.cvssV4Below)
                && Objects.equals(cwe, that.cwe)
                && Objects.equals(cve, that.cve)
                && Objects.equals(vulnerabilityNames, that.vulnerabilityNames)
                && Objects.equals(gav, that.gav)
                && Objects.equals(packageUrl, that.packageUrl)
                && Objects.equals(until, that.until);
    }

    @Override
    public int hashCode() {
        return Objects.hash(base, filePath, sha1, cpe, cvssBelow, cvssV2Below, cvssV3Below, cvssV4Below, cwe, cve, vulnerabilityNames, gav, packageUrl, until);
    }
}
