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

import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.jspecify.annotations.NonNull;
import org.owasp.dependencycheck.dependency.Confidence;

/**
 * In identifier such as a CPE or dependency coordinates (i.e. GAV).
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class GenericIdentifier implements Identifier {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 8683243972735598200L;

    /**
     * The confidence that this is the correct identifier.
     */
    private Confidence confidence;
    /**
     * The value of the identifier
     */
    private final String value;
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
     * Constructs a new Identifier with the specified data.
     *
     * @param value the identifier value
     * @param confidence the confidence level that the identifier is correct
     */
    public GenericIdentifier(String value, Confidence confidence) {
        this.confidence = confidence;
        this.value = value;
        this.url = null;
    }

    /**
     * Constructs a new Identifier with the specified data.
     *
     * @param confidence the confidence level that the identifier is correct
     * @param value the identifier value
     * @param url the identifier URL
     */
    public GenericIdentifier(String value, String url, Confidence confidence) {
        this.confidence = confidence;
        this.value = value;
        this.url = url;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Confidence getConfidence() {
        return confidence;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getValue() {
        return value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getUrl() {
        return url;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getNotes() {
        return notes;
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

    /**
     * {@inheritDoc}
     */
    @Override
    public void setNotes(String notes) {
        this.notes = notes;
    }

    /**
     * Basic implementation of equals.
     *
     * @param obj the identifier to compare
     * @return true if the objects are equal
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof GenericIdentifier)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final GenericIdentifier other = (GenericIdentifier) obj;
        return new EqualsBuilder()
                .append(this.value, other.value)
                .append(this.url, other.url)
                .append(this.confidence, other.confidence)
                .isEquals();
    }

    /**
     * Basic implementation of hasCode.
     *
     * @return the hash code
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(5, 49)
                .append(value)
                .append(url)
                .append(confidence)
                .toHashCode();
    }

    /**
     * Standard implementation of toString; displays identifier value and type.
     *
     * @return a String representation of the object
     */
    @Override
    public String toString() {
        return value;
    }

    /**
     * Implementation of the comparator interface.
     *
     * @param o the object being compared
     * @return an integer indicating the ordering
     */
    @Override
    public int compareTo(@NonNull Identifier o) {
        return new CompareToBuilder()
                .append(this.value, o.toString())
                .append(this.url, o.getUrl())
                .append(this.confidence, o.getConfidence())
                .toComparison();
    }
}
