package org.owasp.dependencycheck.xml.suppression;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.concurrent.NotThreadSafe;

import org.apache.commons.lang3.time.DateFormatUtils;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private List<String> cwe = new ArrayList<>();
    private List<String> cve = new ArrayList<>();
    private final List<PropertyType> vulnerabilityNames = new ArrayList<>();
    private PropertyType gav;
    private PropertyType packageUrl;
    private String notes;
    private boolean base;
    private Calendar until;
    private boolean matched = false;

    // ---------------- getters / setters ----------------

    public void addCpe(PropertyType cpe) { this.cpe.add(cpe); }
    public List<PropertyType> getCpe() { return cpe; }
    public void setCpe(List<PropertyType> cpe) { this.cpe = cpe; }
    public boolean hasCpe() { return !cpe.isEmpty(); }

    public List<String> getCve() { return cve; }
    public void setCve(List<String> cve) { this.cve = cve; }
    public void addCve(String cve) { this.cve.add(cve); }
    public boolean hasCve() { return !cve.isEmpty(); }

    public List<String> getCwe() { return cwe; }
    public void setCwe(List<String> cwe) { this.cwe = cwe; }
    public void addCwe(String cwe) { this.cwe.add(cwe); }
    public boolean hasCwe() { return !cwe.isEmpty(); }

    // -------- CVSS API (tests expect List<Double>) --------

    public List<Double> getCvssBelow() {
        return cvssBelow;
    }

    public void setCvssBelow(List<Double> values) {
        this.cvssBelow = values == null ? new ArrayList<>() : values;
    }

    public boolean hasCvssBelow() { return !cvssBelow.isEmpty(); }
    public void addCvssBelow(Double cvss) { cvssBelow.add(cvss); }

    public List<Double> getCvssV2Below() { return cvssV2Below; }
    public void addCvssV2Below(Double cvss) { cvssV2Below.add(cvss); }
    public boolean hasCvssV2Below() { return !cvssV2Below.isEmpty(); }

    public List<Double> getCvssV3Below() { return cvssV3Below; }
    public void addCvssV3Below(Double cvss) { cvssV3Below.add(cvss); }
    public boolean hasCvssV3Below() { return !cvssV3Below.isEmpty(); }

    public List<Double> getCvssV4Below() { return cvssV4Below; }
    public void addCvssV4Below(Double cvss) { cvssV4Below.add(cvss); }
    public boolean hasCvssV4Below() { return !cvssV4Below.isEmpty(); }

    public boolean isMatched() { return matched; }
    public void setMatched(boolean matched) { this.matched = matched; }

    public Calendar getUntil() { return until; }
    public void setUntil(Calendar until) { this.until = until; }

    public PropertyType getFilePath() { return filePath; }
    public void setFilePath(PropertyType filePath) { this.filePath = filePath; }

    public String getSha1() { return sha1; }
    public void setSha1(String sha1) { this.sha1 = sha1; }

    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }
    public boolean hasNotes() { return notes != null && !notes.isEmpty(); }

    public PropertyType getGav() { return gav; }
    public void setGav(PropertyType gav) { this.gav = gav; }
    public boolean hasGav() { return gav != null; }

    public void setPackageUrl(PropertyType purl) { this.packageUrl = purl; }
    public boolean hasPackageUrl() { return packageUrl != null; }

    public boolean isBase() { return base; }
    public void setBase(boolean base) { this.base = base; }

    public boolean hasVulnerabilityName() { return !vulnerabilityNames.isEmpty(); }
    public List<PropertyType> getVulnerabilityNames() { return vulnerabilityNames; }
    public void addVulnerabilityName(PropertyType name) { vulnerabilityNames.add(name); }

    // ---------------- main logic ----------------

    public void process(Dependency dependency) {

        if (filePath != null && !filePath.matches(dependency.getFilePath())) return;
        if (sha1 != null && !sha1.equalsIgnoreCase(dependency.getSha1sum())) return;

        if (hasGav()) {
            boolean found = false;
            for (Identifier i : dependency.getSoftwareIdentifiers()) {
                if (identifierMatches(gav, i)) { found = true; break; }
            }
            if (!found) return;
        }

        if (hasPackageUrl()) {
            boolean found = false;
            for (Identifier i : dependency.getSoftwareIdentifiers()) {
                if (purlMatches(packageUrl, i)) { found = true; break; }
            }
            if (!found) return;
        }

        if (hasCpe()) {
            final Set<Identifier> removalList = new HashSet<>();

            for (Identifier i : dependency.getVulnerableSoftwareIdentifiers()) {
                for (PropertyType c : cpe) {
                    if (identifierMatches(c, i)) {

                        if (!isBase()) {
                            matched = true;
                            if (notes != null) i.setNotes(notes);
                            dependency.addSuppressedIdentifier(i);

                            for (Vulnerability v : dependency.getVulnerabilities()) {
                                if (notes != null) v.setNotes(notes);
                                dependency.addSuppressedVulnerability(v);
                            }
                        }

                        removalList.add(i);
                        break;
                    }
                }
            }

            removalList.forEach(dependency::removeVulnerableSoftwareIdentifier);
        }

        if (hasCve() || hasVulnerabilityName() || hasCwe()
                || hasCvssBelow() || hasCvssV2Below()
                || hasCvssV3Below() || hasCvssV4Below()) {

            final Set<Vulnerability> removeVulns = new HashSet<>();

            for (Vulnerability v : dependency.getVulnerabilities()) {
                boolean remove = false;

                for (String entry : cve) {
                    if (entry.equalsIgnoreCase(v.getName())) { remove = true; break; }
                }

                if (!remove && !cwe.isEmpty() && v.getCwes() != null) {
                    for (String entry : cwe) {
                        String toMatch = "CWE-" + entry;
                        if (v.getCwes().stream().anyMatch(c -> c.startsWith(toMatch))) {
                            remove = true; break;
                        }
                    }
                }

                if (!remove && v.getName() != null) {
                    for (PropertyType entry : vulnerabilityNames) {
                        if (entry.matches(v.getName())) { remove = true; break; }
                    }
                }

                if (!remove && suppressedBasedOnScore(v)) remove = true;

                if (remove) {
                    removeVulns.add(v);
                    if (!isBase()) {
                        matched = true;
                        if (notes != null) v.setNotes(notes);
                        dependency.addSuppressedVulnerability(v);
                    }
                }
            }

            removeVulns.forEach(dependency::removeVulnerability);
        }
    }

    boolean suppressedBasedOnScore(Vulnerability v) {
        for (Double cvss : cvssBelow) {
            if (v.getCvssV2() != null && v.getCvssV2().getCvssData().getBaseScore() < cvss) return true;
            if (v.getCvssV3() != null && v.getCvssV3().getCvssData().getBaseScore() < cvss) return true;
            if (v.getCvssV4() != null && v.getCvssV4().getCvssData().getBaseScore() < cvss) return true;
        }
        return false;
    }

    // ---- REQUIRED BY TESTS ----
    public boolean cpeHasNoVersion(PropertyType cpe) {
        if (cpe == null || cpe.getValue() == null) return true;
        String v = cpe.getValue();
        return !v.contains(":*") && !v.matches(".*:[0-9].*");
    }

    protected boolean purlMatches(PropertyType suppressionEntry, Identifier identifier) {
        return identifier instanceof PurlIdentifier
                && suppressionEntry.matches(((PurlIdentifier) identifier).toString());
    }

    protected boolean identifierMatches(PropertyType suppressionEntry, Identifier identifier) {
        if (identifier instanceof PurlIdentifier) {
            return suppressionEntry.matches(((PurlIdentifier) identifier).toGav());
        } else if (identifier instanceof CpeIdentifier) {
            try {
                String cpeVal = ((CpeIdentifier) identifier).getCpe().toCpe22Uri();
                return suppressionEntry.isRegex()
                        ? suppressionEntry.matches(cpeVal)
                        : cpeVal.toLowerCase().startsWith(suppressionEntry.getValue().toLowerCase());
            } catch (CpeEncodingException ex) {
                LOGGER.debug("Unable to convert CPE", ex);
            }
        }
        return suppressionEntry.matches(identifier.getValue());
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("SuppressionRule{");
        if (until != null) sb.append("until=").append(DateFormatUtils.ISO_8601_EXTENDED_DATETIME_TIME_ZONE_FORMAT.format(until)).append(',');
        if (filePath != null) sb.append("filePath=").append(filePath).append(',');
        if (sha1 != null) sb.append("sha1=").append(sha1).append(',');
        if (packageUrl != null) sb.append("packageUrl=").append(packageUrl).append(',');
        if (gav != null) sb.append("gav=").append(gav).append(',');
        sb.append('}');
        return sb.toString();
    }
}
