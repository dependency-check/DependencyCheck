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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.dependency;

import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.concurrent.ThreadSafe;

import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.jspecify.annotations.NonNull;
import org.owasp.dependencycheck.analyzer.exception.UnexpectedAnalysisException;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import org.owasp.dependencycheck.utils.DependencyVersion;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.ICpe;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.util.Convert;
import us.springett.parsers.cpe.values.LogicalValue;
import us.springett.parsers.cpe.values.Part;

/**
 * A record containing information about vulnerable software. This is referenced
 * from a vulnerability.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class VulnerableSoftware extends Cpe implements Serializable {

    /**
     * The serial version UID.
     */
    private static final long serialVersionUID = 605319412326651052L;

    /**
     * The ending range, excluding the specified version, for matching
     * vulnerable software
     */
    private final String versionEndExcluding;
    /**
     * The ending range, including the specified version, for matching
     * vulnerable software
     */
    private final String versionEndIncluding;
    /**
     * The starting range, excluding the specified version, for matching
     * vulnerable software
     */
    private final String versionStartExcluding;
    /**
     * the starting range, including the specified version, for matching
     * vulnerable software
     */
    private final String versionStartIncluding;
    /**
     * A flag indicating whether this represents a vulnerable software object.
     */
    private final boolean vulnerable;

    /**
     * Constructs a new immutable VulnerableSoftware object that represents the
     * Well Form Named defined in the CPE 2.3 specification. Specifying
     * <code>null</code> will be set to the default
     * {@link us.springett.parsers.cpe.values.LogicalValue#ANY}. All values
     * passed in must be well formed (i.e. special characters quoted with a
     * backslash).
     *
     * @see <a href="https://cpe.mitre.org/specification/">CPE 2.3</a>
     * @param part the type of entry: application, operating system, or hardware
     * @param vendor the vendor of the CPE entry
     * @param product the product of the CPE entry
     * @param version the version of the CPE entry
     * @param update the update of the CPE entry
     * @param edition the edition of the CPE entry
     * @param language the language of the CPE entry
     * @param swEdition the swEdition of the CPE entry
     * @param targetSw the targetSw of the CPE entry
     * @param targetHw the targetHw of the CPE entry
     * @param other the other of the CPE entry
     * @param versionEndExcluding the ending range, excluding the specified
     * version, for matching vulnerable software
     * @param versionEndIncluding the ending range, including the specified
     * version, for matching vulnerable software
     * @param versionStartExcluding the starting range, excluding the specified
     * version, for matching vulnerable software
     * @param versionStartIncluding the starting range, including the specified
     * version, for matching vulnerable software
     * @param vulnerable whether or not this represents a vulnerable software
     * item
     * @throws CpeValidationException thrown if one of the CPE entries is
     * invalid
     */
    //CSOFF: ParameterNumber
    public VulnerableSoftware(Part part, String vendor, String product, String version,
            String update, String edition, String language, String swEdition,
            String targetSw, String targetHw, String other,
            String versionEndExcluding, String versionEndIncluding, String versionStartExcluding,
            String versionStartIncluding, boolean vulnerable) throws CpeValidationException {
        super(part, vendor, product, version, update, edition, language, swEdition, targetSw, targetHw, other);
        this.versionEndExcluding = versionEndExcluding;
        this.versionEndIncluding = versionEndIncluding;
        this.versionStartExcluding = versionStartExcluding;
        this.versionStartIncluding = versionStartIncluding;
        this.vulnerable = vulnerable;
    }
    //CSON: ParameterNumber

    /**
     * Normalizes null and empty strings to null for consistent comparison.
     * @param s the string to normalize
     * @return null if s is null or empty, otherwise s
     */
    private static String normalizeForComparison(String s) {
        return (s == null || s.isEmpty()) ? null : s;
    }

    @Override
    public int compareTo(@NonNull ICpe o) {
        if (o instanceof VulnerableSoftware) {
            final VulnerableSoftware other = (VulnerableSoftware) o;
            return new CompareToBuilder()
                    .appendSuper(super.compareTo(other))
                    .append(normalizeForComparison(versionStartIncluding), normalizeForComparison(other.versionStartIncluding))
                    .append(normalizeForComparison(versionStartExcluding), normalizeForComparison(other.versionStartExcluding))
                    .append(normalizeForComparison(versionEndIncluding), normalizeForComparison(other.versionEndIncluding))
                    .append(normalizeForComparison(versionEndExcluding), normalizeForComparison(other.versionEndExcluding))
                    .append(this.vulnerable, other.vulnerable)
                    .build();
        } else if (o instanceof Cpe) {
            return super.compareTo(o);
        }
        throw new UnexpectedAnalysisException("Unable to compare " + o.getClass().getCanonicalName());
    }

    @Override
    public int hashCode() {
        // you pick a hard-coded, randomly chosen, non-zero, odd number
        // ideally different for each class
        return new HashCodeBuilder(13, 59)
                .appendSuper(super.hashCode())
                .append(normalizeForComparison(versionEndExcluding))
                .append(normalizeForComparison(versionEndIncluding))
                .append(normalizeForComparison(versionStartExcluding))
                .append(normalizeForComparison(versionStartIncluding))
                .toHashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof VulnerableSoftware)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final VulnerableSoftware rhs = (VulnerableSoftware) obj;
        return new EqualsBuilder()
                .appendSuper(super.equals(obj))
                .append(normalizeForComparison(versionEndExcluding), normalizeForComparison(rhs.versionEndExcluding))
                .append(normalizeForComparison(versionEndIncluding), normalizeForComparison(rhs.versionEndIncluding))
                .append(normalizeForComparison(versionStartExcluding), normalizeForComparison(rhs.versionStartExcluding))
                .append(normalizeForComparison(versionStartIncluding), normalizeForComparison(rhs.versionStartIncluding))
                .isEquals();
    }

    /**
     * <p>
     * Determines if the VulnerableSoftware matches the given target
     * VulnerableSoftware. This does not follow the CPE 2.3 Specification
     * exactly as there are cases where undefined comparisons will result in
     * either true or false. For instance, 'ANY' will match 'm+wild cards' and
     * NA will return false when the target has 'm+wild cards'.</p>
     * <p>
     * For vulnerable software matching, the implementation also takes into
     * account version ranges as specified within the NVD data feeds.</p>
     *
     * @param target the target CPE to evaluate
     * @return <code>true</code> if the CPE matches the target; otherwise
     * <code>false</code>
     */
    @Override
    public boolean matches(ICpe target) {
        boolean result = this.vulnerable;
        result &= compareAttributes(this.getPart(), target.getPart());
        result &= compareAttributes(this.getVendor(), target.getVendor());
        result &= compareAttributes(this.getProduct(), target.getProduct());

        //TODO implement versionStart etc.
        result &= compareVersionRange(target.getVersion());

        //todo - if the vulnerability has an update we are might not be collecting it correctly...
        // as such, this check might cause FN if the CVE has an update in the data set
        result &= compareUpdateAttributes(this.getUpdate(), target.getUpdate());
        result &= compareAttributes(this.getEdition(), target.getEdition());
        result &= compareAttributes(this.getLanguage(), target.getLanguage());
        result &= compareAttributes(this.getSwEdition(), target.getSwEdition());
        result &= compareAttributes(this.getTargetSw(), target.getTargetSw());
        result &= compareAttributes(this.getTargetHw(), target.getTargetHw());
        result &= compareAttributes(this.getOther(), target.getOther());
        return result;
    }

    /**
     * Performs the same operation as Cpe.compareAttributes() - except
     * additional rules are applied to match a1 to alpha1 and the comparison of
     * update attributes will also return true if the only difference between
     * the strings is an underscore or hyphen.
     *
     * @param left the left value to compare
     * @param right the right value to compare
     * @return <code>true</code> if there is a match; otherwise
     * <code>false</code>
     */
    protected static boolean compareUpdateAttributes(String left, String right) {
        //the numbers below come from the CPE Matching standard
        //Table 6-2: Enumeration of Attribute Comparison Set Relations
        //https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf

        if (left.equalsIgnoreCase(right)) {
            //1 6 9 - equals
            return true;
        } else if (LogicalValue.ANY.getAbbreviation().equals(left)) {
            //2 3 4 - superset (4 is undefined - treating as true)
            return true;
        } else if (LogicalValue.NA.getAbbreviation().equals(left)
                && LogicalValue.ANY.getAbbreviation().equals(right)) {
            //5 - subset
            return true;
        } else if (LogicalValue.NA.getAbbreviation().equals(left)) {
            //7 8 - disjoint, undefined
            return false;
        } else if (LogicalValue.NA.getAbbreviation().equals(right)) {
            //12 16 - disjoint
            return false;
        } else if (LogicalValue.ANY.getAbbreviation().equals(right)) {
            //13 15 - subset
            return true;
        }
        final String leftValue = left.replace("-", "").replace("_", "");
        final String rightValue = right.replace("-", "").replace("_", "");
        if (leftValue.equalsIgnoreCase(rightValue)) {
            //1 6 9 - equals
            return true;
        }

        boolean results = false;
        //10 11 14 17
        if (containsSpecialCharacter(left)) {
            final Pattern p = Convert.wellFormedToPattern(left.toLowerCase());
            final Matcher m = p.matcher(right.toLowerCase());
            results = m.matches();
        }
        if (!results && rightValue.matches("^[abu]\\d.*") && leftValue.matches("^(update|alpha|beta).*")) {
            switch (right.charAt(0)) {
                case 'u':
                    results = compareUpdateAttributes(leftValue, "update" + rightValue.substring(1));
                    break;
                case 'a':
                    results = compareUpdateAttributes(leftValue, "alpha" + rightValue.substring(1));
                    break;
                case 'b':
                    results = compareUpdateAttributes(leftValue, "beta" + rightValue.substring(1));
                    break;
                default:
                    break;
            }
        }
        if (!results && leftValue.matches("^[abu]\\d.*") && rightValue.matches("^(update|alpha|beta).*")) {
            switch (left.charAt(0)) {
                case 'u':
                    results = compareUpdateAttributes("update" + leftValue.substring(1), rightValue);
                    break;
                case 'a':
                    results = compareUpdateAttributes("alpha" + leftValue.substring(1), rightValue);
                    break;
                case 'b':
                    results = compareUpdateAttributes("beta" + leftValue.substring(1), rightValue);
                    break;
                default:
                    break;
            }
        }
        return results;
    }

    /**
     * Determines if the string has an unquoted special character.
     *
     * @param value the string to check
     * @return <code>true</code> if the string contains an unquoted special
     * character; otherwise <code>false</code>
     */
    private static boolean containsSpecialCharacter(String value) {
        for (int x = 0; x < value.length(); x++) {
            final char c = value.charAt(x);
            if (c == '?' || c == '*') {
                return true;
            } else if (c == '\\') {
                //skip the next character because it is quoted
                x += 1;
            }
        }
        return false;
    }

    /**
     * Tests if the left matches the right.
     *
     * @param left the cpe to compare
     * @param right the cpe to check
     * @return <code>true</code> if a match is found; otherwise
     * <code>false</code>
     */
    public static boolean testMatch(ICpe left, ICpe right) {
        boolean result = true;
        result &= compareAttributes(left.getPart(), right.getPart());
        result &= compareAttributes(left.getWellFormedVendor(), right.getWellFormedVendor());
        result &= compareAttributes(left.getWellFormedProduct(), right.getWellFormedProduct());

        if (right instanceof VulnerableSoftware) {
            final VulnerableSoftware vs = (VulnerableSoftware) right;
            result &= vs.vulnerable;
            result &= compareVersions(vs, left.getVersion());
        } else if (left instanceof VulnerableSoftware) {
            final VulnerableSoftware vs = (VulnerableSoftware) left;
            result &= vs.vulnerable;
            result &= compareVersions(vs, right.getVersion());
        } else {
            result &= compareAttributes(left.getWellFormedVersion(), right.getWellFormedVersion());
        }

        //todo - if the vulnerability has an update we are might not be collecting it correctly...
        // as such, this check might cause FN if the CVE has an update in the data set
        result &= compareUpdateAttributes(left.getWellFormedUpdate(), right.getWellFormedUpdate());
        result &= compareAttributes(left.getWellFormedEdition(), right.getWellFormedEdition());
        result &= compareAttributes(left.getWellFormedLanguage(), right.getWellFormedLanguage());
        result &= compareAttributes(left.getWellFormedSwEdition(), right.getWellFormedSwEdition());
        result &= compareAttributes(left.getWellFormedTargetSw(), right.getWellFormedTargetSw());
        result &= compareAttributes(left.getWellFormedTargetHw(), right.getWellFormedTargetHw());
        result &= compareAttributes(left.getWellFormedOther(), right.getWellFormedOther());
        return result;
    }

    /**
     * <p>
     * Determines if the target VulnerableSoftware matches the
     * VulnerableSoftware. This does not follow the CPE 2.3 Specification
     * exactly as there are cases where undefined comparisons will result in
     * either true or false. For instance, 'ANY' will match 'm+wild cards' and
     * NA will return false when the target has 'm+wild cards'.</p>
     * <p>
     * For vulnerable software matching, the implementation also takes into
     * account version ranges as specified within the NVD data feeds.</p>
     *
     * @param target the VulnerableSoftware to evaluate
     * @return <code>true</code> if the target CPE matches CPE; otherwise
     * <code>false</code>
     */
    @Override
    public boolean matchedBy(ICpe target) {
        return testMatch(target, this);
    }

    /**
     * Evaluates the target against the version and version range checks:
     * versionEndExcluding, versionStartExcluding versionEndIncluding, and
     * versionStartIncluding.
     *
     * @param targetVersion the version to compare
     * @return <code>true</code> if the target version is matched; otherwise
     * <code>false</code>
     */
    protected boolean compareVersionRange(String targetVersion) {
        return compareVersions(this, targetVersion);
    }

    /**
     * Evaluates the target against the version and version range checks:
     * versionEndExcluding, versionStartExcluding versionEndIncluding, and
     * versionStartIncluding.
     *
     * @param vs a reference to the vulnerable software to compare
     * @param targetVersion the version to compare
     * @return <code>true</code> if the target version is matched; otherwise
     * <code>false</code>
     */
    protected static boolean compareVersions(VulnerableSoftware vs, String targetVersion) {
        if (LogicalValue.NA.getAbbreviation().equals(vs.getVersion())) {
            return false;
        }
        //if any of the four conditions will be evaluated - then true;
        boolean result = (vs.versionEndExcluding != null && !vs.versionEndExcluding.isEmpty())
                || (vs.versionStartExcluding != null && !vs.versionStartExcluding.isEmpty())
                || (vs.versionEndIncluding != null && !vs.versionEndIncluding.isEmpty())
                || (vs.versionStartIncluding != null && !vs.versionStartIncluding.isEmpty());

        if (!result && compareAttributes(vs.getVersion(), targetVersion)) {
            return true;
        }

        final DependencyVersion target = new DependencyVersion(targetVersion);
        if (target.getVersionParts().isEmpty()) {
            return false;
        }
        if (result && vs.versionEndExcluding != null && !vs.versionEndExcluding.isEmpty()) {
            final DependencyVersion endExcluding = new DependencyVersion(vs.versionEndExcluding);
            result = endExcluding.compareTo(target) > 0;
        }
        if (result && vs.versionStartExcluding != null && !vs.versionStartExcluding.isEmpty()) {
            final DependencyVersion startExcluding = new DependencyVersion(vs.versionStartExcluding);
            result = startExcluding.compareTo(target) < 0;
        }
        if (result && vs.versionEndIncluding != null && !vs.versionEndIncluding.isEmpty()) {
            final DependencyVersion endIncluding = new DependencyVersion(vs.versionEndIncluding);
            result &= endIncluding.compareTo(target) >= 0;
        }
        if (result && vs.versionStartIncluding != null && !vs.versionStartIncluding.isEmpty()) {
            final DependencyVersion startIncluding = new DependencyVersion(vs.versionStartIncluding);
            result &= startIncluding.compareTo(target) <= 0;
        }
        return result;
    }

    /**
     * Returns the versionEndExcluding.
     *
     * @return the versionEndExcluding
     */
    public String getVersionEndExcluding() {
        return versionEndExcluding;
    }

    /**
     * Returns the versionEndIncluding.
     *
     * @return the versionEndIncluding
     */
    public String getVersionEndIncluding() {
        return versionEndIncluding;
    }

    /**
     * Returns the versionStartExcluding.
     *
     * @return the versionStartExcluding
     */
    public String getVersionStartExcluding() {
        return versionStartExcluding;
    }

    /**
     * Returns the versionStartIncluding.
     *
     * @return the versionStartIncluding
     */
    public String getVersionStartIncluding() {
        return versionStartIncluding;
    }

    /**
     * Returns the value of vulnerable.
     *
     * @return the value of vulnerable
     */
    public boolean isVulnerable() {
        return vulnerable;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append(this.toCpe23FS());
        boolean textAdded = false;
        if (versionStartIncluding != null && !versionStartIncluding.isEmpty()) {
            sb.append(" versions from (including) ")
                    .append(versionStartIncluding);
            textAdded = true;
        }
        if (versionStartExcluding != null && !versionStartExcluding.isEmpty()) {
            if (textAdded) {
                sb.append(";");
            }
            sb.append(" versions from (excluding) ")
                    .append(versionStartExcluding);
            textAdded = true;
        }
        if (versionEndIncluding != null && !versionEndIncluding.isEmpty()) {
            if (textAdded) {
                sb.append(";");
            }
            sb.append(" versions up to (including) ")
                    .append(versionEndIncluding);
            textAdded = true;
        }
        if (versionEndExcluding != null && !versionEndExcluding.isEmpty()) {
            if (textAdded) {
                sb.append(";");
            }
            sb.append(" versions up to (excluding) ")
                    .append(versionEndExcluding);
            textAdded = true;
        }
        if (!vulnerable) {
            if (textAdded) {
                sb.append(";");
            }
            sb.append(" version is NOT VULNERABLE");
        }
        return sb.toString();
    }

    /**
     * Returns the NVD search URL for this vulnerable software.
     *
     * @return the NVD search URL
     */
    public String toNvdSearchUrl() {
        return CpeIdentifier.nvdSearchUrlFor(this);
    }
}
