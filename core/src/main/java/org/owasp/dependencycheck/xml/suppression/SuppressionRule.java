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
 * Copyright (c) 2013 Jeremy Long.
 */
package org.owasp.dependencycheck.xml.suppression;

import java.util.concurrent.ConcurrentHashMap;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.annotation.concurrent.NotThreadSafe;

import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;

@NotThreadSafe
public class SuppressionRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(SuppressionRule.class);

    private PropertyType filePath;
    private String sha1;
    private List<PropertyType> cpe = new ArrayList<>();
    private List<Double> cvssBelow = new ArrayList<>();
    private List<Double> cvssV2Below = new ArrayList<>();
    private List<Double> cvssV3Below = new ArrayList<>();
    private List<Double> cvssV4Below = new ArrayList<>();
    private List<PropertyType> cwe = new ArrayList<>();
    private final List<PropertyType> vulnerabilityNames = new ArrayList<>();
    private PropertyType gav;
    private PropertyType packageUrl;
    private String notes;
    private boolean base;
    private Calendar until;
    // Suppression entry tracking
    private final Set<SuppressionEntry> allEntries = ConcurrentHashMap.newKeySet();

    // ----------------- getters/setters -----------------
    
    public Calendar getUntil() { return until; }
    public void setUntil(Calendar until) { this.until = until; }

    public PropertyType getFilePath() { return filePath; }
    public void setFilePath(PropertyType filePath) { this.filePath = filePath; }

    public String getSha1() { return sha1; }
    public void setSha1(String sha1) { this.sha1 = sha1; }

    public boolean isBase() { return base; }
    public void setBase(boolean base) { this.base = base; }

    public void setGav(PropertyType gav) { this.gav = gav; }
    public boolean hasGav() { return gav != null; }

    public void setPackageUrl(PropertyType purl) { this.packageUrl = purl; }
    public boolean hasPackageUrl() { return packageUrl != null; }

    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }

    // ----------------- add methods -----------------

    public void addCpe(PropertyType cpe) {
        this.cpe.add(cpe);
        track(SuppressionEntry.Type.CPE, cpe);
    }

    public void addVulnerabilityName(PropertyType name) {
        this.vulnerabilityNames.add(name);
        track(SuppressionEntry.Type.VULNERABILITY_NAME, name);
    }

public void addCwe(String cwe) {
    PropertyType pt = new PropertyType(cwe);
    this.cwe.add(pt);
    track(SuppressionEntry.Type.CWE, pt);
}

    public void addCve(String cve) {
        this.cve.add(cve);
        track(SuppressionEntry.Type.CVE, new PropertyType(cve));
    }

    public void addCvssBelow(Double cvss) {
        this.cvssBelow.add(cvss);
        track(SuppressionEntry.Type.CVSS, null);
    }

    public void addCvssV2Below(Double cvss) { cvssV2Below.add(cvss); }
    public void addCvssV3Below(Double cvss) { cvssV3Below.add(cvss); }
    public void addCvssV4Below(Double cvss) { cvssV4Below.add(cvss); }

    private void track(SuppressionEntry.Type type, PropertyType value) {
        if (!isBase()) {
            allEntries.add(new SuppressionEntry(type, value));
        }
    }

    // ----------------- checks -----------------

    public boolean hasCpe() { return !cpe.isEmpty(); }
    public boolean hasCwe() { return !cwe.isEmpty(); }
    public boolean hasCve() { return !cve.isEmpty(); }
    public boolean hasVulnerabilityName() { return !vulnerabilityNames.isEmpty(); }
    public boolean hasCvssBelow() { return !cvssBelow.isEmpty(); }
    public boolean hasCvssV2Below() { return !cvssV2Below.isEmpty(); }
    public boolean hasCvssV3Below() { return !cvssV3Below.isEmpty(); }
    public boolean hasCvssV4Below() { return !cvssV4Below.isEmpty(); }

    // ----------------- processing -----------------

    public void process(Dependency dependency) {

        if (filePath != null && !filePath.matches(dependency.getFilePath())) return;
        if (sha1 != null && !sha1.equalsIgnoreCase(dependency.getSha1sum())) return;

        if (hasGav() && !matchIdentifier(dependency, gav)) return;
        if (hasPackageUrl() && !matchPurl(dependency, packageUrl)) return;

// ---- CPE suppression ----
if (hasCpe()) {
    List<Identifier> identifiersToRemove = new ArrayList<>();

    for (Identifier i : new ArrayList<>(dependency.getVulnerableSoftwareIdentifiers())) {
        for (PropertyType c : cpe) {
            if (identifierMatches(c, i)) {
                suppressByCpeMatch(dependency, i);
                identifiersToRemove.add(i);
                break;
            }
        }
    }

    for (Identifier i : identifiersToRemove) {
        dependency.removeVulnerableSoftwareIdentifier(i);
    }
}

        // ---- Vulnerability suppression ----
        Set<Vulnerability> removeVulns = new HashSet<>();
        for (Vulnerability v : dependency.getVulnerabilities()) {

            boolean remove = matchesCve(v)
                    || matchesCwe(v)
                    || matchesVulnerabilityName(v)
                    || suppressedByCvss(v);

            if (remove) {
                suppressVulnerability(dependency, v);
                removeVulns.add(v);
            }
        }

        removeVulns.forEach(dependency::removeVulnerability);
    }
private void suppressIdentifier(Dependency dep, Identifier id) {
    if (!isBase()) {
        if (notes != null) id.setNotes(notes);
        dep.addSuppressedIdentifier(id);
    }
    
}
    private void suppressVulnerability(Dependency dep, Vulnerability v) {
    if (!isBase()) {
        if (notes != null) v.setNotes(notes);
        dep.addSuppressedVulnerability(v);
    }
}

    // ----------------- match helpers -----------------

private boolean matchesCve(Vulnerability v) {
    for (String entry : cve) {
        if (entry.equalsIgnoreCase(v.getName())) {
            return true;
        }
    }
    return false;
}

private boolean matchesCwe(Vulnerability v) {
    if (v.getCwes() == null) return false;

    for (PropertyType rule : cwe) {
        for (String vulnCwe : v.getCwes()) {
            if (rule.matches(vulnCwe)) {
                return true;
            }
        }
    }
    return false;
}

    private boolean matchesVulnerabilityName(Vulnerability v) {
        if (v.getName() == null) return false;
        for (PropertyType pt : vulnerabilityNames) {
            if (pt.matches(v.getName())) return true;
        }
        return false;
    }

    private boolean suppressedByCvss(Vulnerability v) {

        if (!cvssBelow.isEmpty()) {
            for (Double threshold : cvssBelow) {
                if (scoreBelow(v, threshold)) return true;
            }
            return false;
        }

        if (hasCvssV2Below() || hasCvssV3Below() || hasCvssV4Below()) {
            return versionedCvssCheck(v);
        }

        return false;
    }

    private boolean scoreBelow(Vulnerability v, double t) {
        if (v.getCvssV2() != null && v.getCvssV2().getCvssData().getBaseScore() < t) return true;
        if (v.getCvssV3() != null && v.getCvssV3().getCvssData().getBaseScore() < t) return true;
        if (v.getCvssV4() != null && v.getCvssV4().getCvssData().getBaseScore() < t) return true;
        return false;
    }

    private boolean versionedCvssCheck(Vulnerability v) {

        Double t2 = cvssV2Below.stream().max(Double::compare).orElse(11.0);
        Double t3 = cvssV3Below.stream().max(Double::compare).orElse(11.0);
        Double t4 = cvssV4Below.stream().max(Double::compare).orElse(11.0);

        Double s2 = v.getCvssV2() != null ? v.getCvssV2().getCvssData().getBaseScore() : null;
        Double s3 = v.getCvssV3() != null ? v.getCvssV3().getCvssData().getBaseScore() : null;
        Double s4 = v.getCvssV4() != null ? v.getCvssV4().getCvssData().getBaseScore() : null;

        boolean ok2 = s2 == null || s2 < t2;
        boolean ok3 = s3 == null || s3 < t3;
        boolean ok4 = s4 == null || s4 < t4;

        return ok2 && ok3 && ok4;
    }

    private boolean matchIdentifier(Dependency dep, PropertyType rule) {
        for (Identifier i : dep.getSoftwareIdentifiers()) {
            if (identifierMatches(rule, i)) return true;
        }
        return false;
    }

    private boolean matchPurl(Dependency dep, PropertyType rule) {
        for (Identifier i : dep.getSoftwareIdentifiers()) {
            if (purlMatches(rule, i)) return true;
        }
        return false;
    }

    protected boolean purlMatches(PropertyType suppressionEntry, Identifier identifier) {
        if (identifier instanceof PurlIdentifier) {
            return suppressionEntry.matches(identifier.getValue());
        }
        return false;
    }

    protected boolean identifierMatches(PropertyType suppressionEntry, Identifier identifier) {
        if (identifier instanceof CpeIdentifier) {
            try {
                Cpe cpeId = ((CpeIdentifier) identifier).getCpe();
                return suppressionEntry.matches(cpeId.toCpe22Uri());
            } catch (CpeEncodingException ex) {
                LOGGER.debug("CPE conversion error", ex);
            }
        }
        return suppressionEntry.matches(identifier.getValue());
    }

    @Override
    public String toString() {
        return "SuppressionRule{" +
                "filePath=" + filePath +
                ", sha1=" + sha1 +
                ", cpe=" + cpe +
                ", cwe=" + cwe +
                ", cve=" + cve +
                ", vulnerabilityNames=" + vulnerabilityNames +
                ", cvssBelow=" + cvssBelow +
                ", cvssV2Below=" + cvssV2Below +
                ", cvssV3Below=" + cvssV3Below +
                ", cvssV4Below=" + cvssV4Below +
                ", gav=" + gav +
                ", packageUrl=" + packageUrl +
                ", base=" + base +
                '}';
    }
}
