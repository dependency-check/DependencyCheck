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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cpe;

import java.io.Serializable;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

/**
 * A CPE entry containing the name, vendor, product, and version.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class IndexEntry implements Serializable {

    /**
     * the serial version uid.
     */
    private static final long serialVersionUID = 8011924485946326934L;
    /**
     * The vendor name.
     */
    private String vendor;
    /**
     * The documentId.
     */
    private int documentId;
    /**
     * The product name.
     */
    private String product;
    /**
     * The search score.
     */
    private float searchScore;

    /**
     * Get the value of documentId.
     *
     * @return the value of documentId
     */
    public int getDocumentId() {
        return documentId;
    }

    /**
     * Set the value of documentId.
     *
     * @param documentId new value of documentId
     */
    public void setDocumentId(int documentId) {
        this.documentId = documentId;
    }

    /**
     * Get the value of vendor.
     *
     * @return the value of vendor
     */
    public String getVendor() {
        return vendor;
    }

    /**
     * Set the value of vendor.
     *
     * @param vendor new value of vendor
     */
    public void setVendor(String vendor) {
        this.vendor = vendor;
    }

    /**
     * Get the value of product.
     *
     * @return the value of product
     */
    public String getProduct() {
        return product;
    }

    /**
     * Set the value of product.
     *
     * @param product new value of product
     */
    public void setProduct(String product) {
        this.product = product;
    }

    /**
     * Get the value of searchScore.
     *
     * @return the value of searchScore
     */
    public float getSearchScore() {
        return searchScore;
    }

    /**
     * Set the value of searchScore.
     *
     * @param searchScore new value of searchScore
     */
    public void setSearchScore(float searchScore) {
        this.searchScore = searchScore;
    }

    /**
     * <p>
     * Parses a name attribute value, from the cpe.xml, into its corresponding
     * parts: vendor, product.</p>
     * <p>
     * Example:</p>
     * <code>nbsp;nbsp;nbsp;cpe:/a:apache:struts:1.1:rc2</code>
     *
     * <p>
     * Results in:</p> <ul> <li>Vendor: apache</li> <li>Product: struts</li>
     * </ul>
     * <p>
     * If it is necessary to parse the CPE into more parts (i.e. to include
     * version and revision) then you should use the `cpe-parser`.
     *
     * @param cpeName the CPE name
     */
    public void parseName(String cpeName) {
        if (cpeName != null && cpeName.length() > 7) {
            final String cpeNameWithoutPrefix = cpeName.substring(7);
            final String[] data = StringUtils.split(cpeNameWithoutPrefix, ':');
            if (data.length >= 1) {
                vendor = URLDecoder.decode(data[0].replace("+", "%2B"), StandardCharsets.UTF_8);
                if (data.length >= 2) {
                    product = URLDecoder.decode(data[1].replace("+", "%2B"), StandardCharsets.UTF_8);
                }
            }
        }
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(5, 27)
                .append(documentId)
                .append(vendor)
                .append(product)
                .append(searchScore)
                .build();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof IndexEntry)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final IndexEntry rhs = (IndexEntry) obj;
        return new EqualsBuilder()
                .append(vendor, rhs.vendor)
                .append(product, rhs.product)
                .isEquals();
    }

    /**
     * Standard implementation of toString showing vendor and product.
     *
     * @return the string representation of the object
     */
    @Override
    public String toString() {
        return "IndexEntry{" + "vendor=" + vendor + ", product=" + product + "', score=" + searchScore + "}";
    }
}
