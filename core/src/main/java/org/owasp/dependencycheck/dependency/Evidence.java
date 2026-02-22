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
package org.owasp.dependencycheck.dependency;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.jspecify.annotations.NonNull;

import java.io.Serializable;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Evidence is a piece of information about a Dependency.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class Evidence implements Serializable, Comparable<Evidence> {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 2402386455919067874L;

    /**
     * The name of the evidence.
     */
    private String name;

    /**
     * The source of the evidence.
     */
    private String source;

    /**
     * The value of the evidence.
     */
    private String value;

    /**
     * The confidence level for the evidence.
     */
    private Confidence confidence;

    /**
     * Whether the evidence originates from a hint.
     */
    private boolean fromHint;

    /**
     * Creates a new Evidence object.
     */
    public Evidence() {
    }

    /**
     * Creates a new Evidence objects.
     *
     * @param source     the source of the evidence.
     * @param name       the name of the evidence.
     * @param value      the value of the evidence.
     * @param confidence the confidence of the evidence.
     */
    public Evidence(String source, String name, String value, Confidence confidence) {
        this(source, name, value, confidence, false);
    }

    /**
     * Creates a new Evidence objects.
     *
     * @param source     the source of the evidence.
     * @param name       the name of the evidence.
     * @param value      the value of the evidence.
     * @param confidence the confidence of the evidence.
     * @param fromHint whether the evidence was introduced by a hint.
     */
    public Evidence(String source, String name, String value, Confidence confidence, boolean fromHint) {
        this.source = source;
        this.name = name;
        this.value = value;
        this.confidence = confidence;
        this.fromHint = fromHint;
    }

    /**
     * Get the value of name.
     *
     * @return the value of name
     */
    public String getName() {
        return name;
    }

    /**
     * Set the value of name.
     *
     * @param name new value of name
     */
    public void setName(String name) {
        this.name = name;
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
     * Get the value of value.
     *
     * @return the value of value
     */
    public String getValue() {
        return value;
    }

    /**
     * Set the value of value.
     *
     * @param value new value of value
     */
    public void setValue(String value) {
        this.value = value;
    }

    /**
     * Get the value of confidence.
     *
     * @return the value of confidence
     */
    public Confidence getConfidence() {
        return confidence;
    }

    /**
     * Set the value of confidence.
     *
     * @param confidence new value of confidence
     */
    public void setConfidence(Confidence confidence) {
        this.confidence = confidence;
    }

    /**
     * Get the value of fromHint.
     *
     * @return the value of fromHint
     */
    public boolean isFromHint() {
        return fromHint;
    }

    /**
     * Set the value of fromHint.
     *
     * @param fromHint new value of fromHint
     */
    public void setFromHint(boolean fromHint) {
        this.fromHint = fromHint;
    }

    /**
     * Implements the hashCode for Evidence.
     *
     * @return hash code.
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(303, 367)
                .append(StringUtils.lowerCase(name))
                .append(StringUtils.lowerCase(source))
                .append(StringUtils.lowerCase(value))
                .append(confidence)
                .toHashCode();
    }

    /**
     * Implements equals for Evidence.
     *
     * @param obj an object to check the equality of.
     * @return whether the two objects are equal.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Evidence)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final Evidence o = (Evidence) obj;
        return new EqualsBuilder()
                .append(this.source == null ? null : this.source.toLowerCase(), o.source == null ? null : o.source.toLowerCase())
                .append(this.name == null ? null : this.name.toLowerCase(), o.name == null ? null : o.name.toLowerCase())
                .append(this.value == null ? null : this.value.toLowerCase(), o.value == null ? null : o.value.toLowerCase())
                .append(this.confidence, o.getConfidence())
                .append(this.fromHint, o.isFromHint())
                .build();
    }

    /**
     * Implementation of the comparable interface.
     *
     * @param o the evidence being compared
     * @return an integer indicating the ordering of the two objects
     */
    @Override
    public int compareTo(@NonNull Evidence o) {
        return new CompareToBuilder()
                .append(this.source == null ? null : this.source.toLowerCase(), o.source == null ? null : o.source.toLowerCase())
                .append(this.name == null ? null : this.name.toLowerCase(), o.name == null ? null : o.name.toLowerCase())
                .append(this.value == null ? null : this.value.toLowerCase(), o.value == null ? null : o.value.toLowerCase())
                .append(this.confidence, o.getConfidence())
                .append(this.fromHint, o.isFromHint())
                .toComparison();
    }

    /**
     * Standard toString() implementation.
     *
     * @return the string representation of the object
     */
    @Override
    public String toString() {
        return "Evidence{" + "name=" + name + ", source=" + source + ", value=" + value + ", confidence=" + confidence
                + ", fromHint=" + fromHint + '}';
    }
}
