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
package org.owasp.dependencycheck.dependency.naming;

import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.hc.core5.net.PercentCodec;
import org.jspecify.annotations.NonNull;
import org.owasp.dependencycheck.dependency.Confidence;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeBuilder;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * A CPE Identifier for a dependency object.
 *
 * @author Jeremy Long
 */
public class CpeIdentifier implements Identifier {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 2901855131887281680L;

    /**
     * The CPE identifier.
     */
    private final Cpe cpe;
    /**
     * The confidence that this is the correct identifier.
     */
    private Confidence confidence;
    /**
     * The URL for the identifier.
     */
    private String url;
    /**
     * Notes about the vulnerability. Generally used for suppression
     * information.
     */
    private String notes;

    /**
     * Constructs a new CPE Identifier from a CPE object with the given
     * confidence.
     *
     * @param cpe the CPE value
     * @param confidence the confidence in the identifiers match
     */
    public CpeIdentifier(Cpe cpe, Confidence confidence) {
        this.cpe = cpe;
        this.confidence = confidence;
        this.url = null;
    }

    /**
     * Constructs a new CPE Identifier from a CPE object with the given
     * confidence.
     *
     * @param cpe the CPE value
     * @param url the URL for the identifier
     * @param confidence the confidence in the identifiers match
     */
    public CpeIdentifier(Cpe cpe, String url, Confidence confidence) {
        this.cpe = cpe;
        this.confidence = confidence;
        this.url = url;
    }

    /**
     * Constructs a new CPE Identifier from a CPE object with the given
     * confidence.
     *
     * @param vendor the vendor
     * @param product the product name
     * @param version the version
     * @param confidence the confidence in the identifiers match
     * @throws CpeValidationException thrown if there is an error converting the
     * vendor, product, and version into a CPE object
     */
    public CpeIdentifier(String vendor, String product, String version, Confidence confidence) throws CpeValidationException {
        final CpeBuilder builder = new CpeBuilder();
        this.cpe = builder.part(Part.APPLICATION).vendor(vendor).product(product).version(version).build();
        this.confidence = confidence;
    }

    /**
     * Returns the CPE object.
     *
     * @return the CPE object
     */
    public Cpe getCpe() {
        return cpe;
    }

    @Override
    public Confidence getConfidence() {
        return confidence;
    }

    @Override
    public String getNotes() {
        return notes;
    }

    @Override
    public String getUrl() {
        return url;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setConfidence(Confidence confidence) {
        this.confidence = confidence;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setUrl(String url) {
        this.url = url;
    }

    @Override
    public void setNotes(String notes) {
        this.notes = notes;
    }

    @Override
    public String getValue() {
        return cpe.toCpe23FS();
    }

    /**
     * Returns the CPE 2.3 formatted string.
     *
     * @return the CPE 2.3 formatted string
     */
    @Override
    public String toString() {
        return cpe.toCpe23FS();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(95, 183)
                .append(this.cpe)
                .append(this.confidence)
                .append(this.url)
                .append(this.notes)
                .toHashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof CpeIdentifier)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final CpeIdentifier other = (CpeIdentifier) obj;
        return new EqualsBuilder().append(cpe, other.cpe)
                .append(this.confidence, other.confidence)
                .append(this.url, other.url)
                .append(this.notes, other.notes).isEquals();
    }

    @Override
    public int compareTo(@NonNull Identifier o) {
        if (o instanceof CpeIdentifier) {
            final CpeIdentifier other = (CpeIdentifier) o;
            return new CompareToBuilder()
                    .append(this.cpe, other.cpe)
                    .append(this.url, other.getUrl())
                    .append(this.confidence, other.getConfidence())
                    .toComparison();

        }
        return new CompareToBuilder()
                .append(this.toString(), o.toString())
                .append(this.url, o.getUrl())
                .append(this.confidence, o.getConfidence())
                .toComparison();
    }

    /**
     * Produces an NVD search URL for a given CPE to find all applicable vulnerabilities, including all populated parts
     * of the given CPE.
     * <p/>
     * The opened link should be sorted in descending order (sortDirection=2) by publish date (sortOrder=3).
     */
    public static String nvdSearchUrlFor(Cpe cpe) {
        // Use PercentCodec to force `*` to be encoded for CPE strings inside the URL. Technically '*' is not a reserved
        // character in the fragment of URLs, but not all browsers handle this consistently, so better to encode aggressively.
        // URlEncoder does not distinguish between parts of URLs appropriately, as well as not forcing encoding of these.
        return String.format("https://nvd.nist.gov/vuln/search#/nvd/home?sortOrder=3&sortDirection=2&cpeFilterMode=applicability&resultType=records&cpeName=%s",
                PercentCodec.encode(cpe.toCpe23FS(), UTF_8));
    }

    /**
     * Produces an NVD search URL for a given application vendor/product/version combination to find all applicable vulnerabilities.
     * <p/>
     * The opened link should be sorted in descending order (sortDirection=2) by publish date (sortOrder=3).
     */
    public static String nvdSearchUrlFor(String vendor, String product, String version) throws CpeValidationException {
        return nvdSearchUrlFor(new CpeBuilder().part(Part.APPLICATION).vendor(vendor).product(product).version(version).build());
    }

    /**
     * Produces an NVD search URL for a given CPE to find all applicable vulnerabilities, including only the part, vendor,
     * and product of the given CPE (if populated). Discards all other parts/discriminators of the CPE in the generated search.
     * <p/>
     * The opened link should be sorted in descending order (sortDirection=2) by publish date (sortOrder=3).
     */
    public static String nvdProductSearchUrlFor(Cpe cpe) {
        try {
            return nvdSearchUrlFor(new CpeBuilder().part(cpe.getPart()).vendor(cpe.getVendor()).product(cpe.getProduct()).build());
        } catch (CpeValidationException e) {
            throw new RuntimeException(e);
        }
    }
}
