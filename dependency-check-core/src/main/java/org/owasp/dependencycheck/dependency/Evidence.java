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

import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.lang.StringUtils;

import java.io.Serializable;

/**
 * Evidence is a piece of information about a Dependency.
 *
 * @author Jeremy Long
 */
public class Evidence implements Serializable, Comparable<Evidence> {

    public static final int MAGIC_HASH_INIT_VALUE = 3;
    public static final int MAGIC_HASH_MULTIPLIER = 67;

    /**
     * Creates a new Evidence object.
     */
    public Evidence() {
    }

    /**
     * Creates a new Evidence objects.
     *
     * @param source the source of the evidence.
     * @param name the name of the evidence.
     * @param value the value of the evidence.
     * @param confidence the confidence of the evidence.
     */
    public Evidence(String source, String name, String value, Confidence confidence) {
        this.source = source;
        this.name = name;
        this.value = value;
        this.confidence = confidence;
    }
    /**
     * The name of the evidence.
     */
    private String name;

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
     * The source of the evidence.
     */
    private String source;

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
     * The value of the evidence.
     */
    private String value;

    /**
     * Get the value of value.
     *
     * @return the value of value
     */
    public String getValue() {
        used = true;
        return value;
    }

    /**
     * Get the value of value. If setUsed is set to false this call to get will not mark the evidence as used.
     *
     * @param setUsed whether or not this call to getValue should cause the used flag to be updated
     * @return the value of value
     */
    public String getValue(Boolean setUsed) {
        used = used || setUsed;
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
     * A value indicating if the Evidence has been "used" (aka read).
     */
    private boolean used;

    /**
     * Get the value of used.
     *
     * @return the value of used
     */
    public boolean isUsed() {
        return used;
    }

    /**
     * Set the value of used.
     *
     * @param used new value of used
     */
    public void setUsed(boolean used) {
        this.used = used;
    }
    /**
     * The confidence level for the evidence.
     */
    private Confidence confidence;

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
     * Implements the hashCode for Evidence.
     *
     * @return hash code.
     */
    @Override
    public int hashCode() {
        int hash = MAGIC_HASH_INIT_VALUE;
        hash = MAGIC_HASH_MULTIPLIER * hash + ObjectUtils.hashCode(StringUtils.lowerCase(this.name));
        hash = MAGIC_HASH_MULTIPLIER * hash + ObjectUtils.hashCode(StringUtils.lowerCase(this.source));
        hash = MAGIC_HASH_MULTIPLIER * hash + ObjectUtils.hashCode(StringUtils.lowerCase(this.value));
        hash = MAGIC_HASH_MULTIPLIER * hash + ObjectUtils.hashCode(this.confidence);
        return hash;
    }

    /**
     * Implements equals for Evidence.
     *
     * @param that an object to check the equality of.
     * @return whether the two objects are equal.
     */
    @Override
    public boolean equals(Object that) {
        if (this == that) {
            return true;
        }
        if (!(that instanceof Evidence)) {
            return false;
        }
        final Evidence e = (Evidence) that;

        return testEquality(name, e.name) && testEquality(source, e.source) && testEquality(value, e.value)
                && (confidence == null ? e.confidence == null : confidence == e.confidence);
    }

    /**
     * Simple equality test for use within the equals method. This does a case insensitive compare.
     *
     * @param l a string to compare.
     * @param r another string to compare.
     * @return whether the two strings are the same.
     */
    private boolean testEquality(String l, String r) {
        return l == null ? r == null : l.equalsIgnoreCase(r);
    }

    /**
     * Implementation of the comparable interface.
     *
     * @param o the evidence being compared
     * @return an integer indicating the ordering of the two objects
     */
    public int compareTo(Evidence o) {
        if (o == null) {
            return 1;
        }
        if (equalsWithNullCheck(source, o.source)) {
            if (equalsWithNullCheck(name, o.name)) {
                if (equalsWithNullCheck(value, o.value)) {
                    if (equalsWithNullCheck(confidence, o.confidence)) {
                        return 0; //they are equal
                    } else {
                        return compareToWithNullCheck(confidence, o.confidence);
                    }
                } else {
                    return compareToIgnoreCaseWithNullCheck(value, o.value);
                }
            } else {
                return compareToIgnoreCaseWithNullCheck(name, o.name);
            }
        } else {
            return compareToIgnoreCaseWithNullCheck(source, o.source);
        }
    }

    /**
     * Equality check with an exhaustive, possibly duplicative, check against nulls.
     *
     * @param me the value to be compared
     * @param other the other value to be compared
     * @return true if the values are equal; otherwise false
     */
    private boolean equalsWithNullCheck(String me, String other) {
        if (me == null && other == null) {
            return true;
        } else if (me == null || other == null) {
            return false;
        }
        return me.equalsIgnoreCase(other);
    }

    /**
     * Equality check with an exhaustive, possibly duplicative, check against nulls.
     *
     * @param me the value to be compared
     * @param other the other value to be compared
     * @return true if the values are equal; otherwise false
     */
    private boolean equalsWithNullCheck(Confidence me, Confidence other) {
        if (me == null && other == null) {
            return true;
        } else if (me == null || other == null) {
            return false;
        }
        return me.equals(other);
    }

    /**
     * Wrapper around {@link java.lang.String#compareToIgnoreCase(java.lang.String) String.compareToIgnoreCase} with an
     * exhaustive, possibly duplicative, check against nulls.
     *
     * @param me the value to be compared
     * @param other the other value to be compared
     * @return true if the values are equal; otherwise false
     */
    private int compareToIgnoreCaseWithNullCheck(String me, String other) {
        if (me == null && other == null) {
            return 0;
        } else if (me == null) {
            return -1; //the other string is greater then me
        } else if (other == null) {
            return 1; //me is greater then the other string
        }
        return me.compareToIgnoreCase(other);
    }

    /**
     * Wrapper around {@link java.lang.Enum#compareTo(java.lang.Enum) Enum.compareTo} with an exhaustive, possibly duplicative,
     * check against nulls.
     *
     * @param me the value to be compared
     * @param other the other value to be compared
     * @return true if the values are equal; otherwise false
     */
    private int compareToWithNullCheck(Confidence me, Confidence other) {
        if (me == null && other == null) {
            return 0;
        } else if (me == null) {
            return -1; //the other string is greater then me
        } else if (other == null) {
            return 1; //me is greater then the other string
        }
        return me.compareTo(other);
    }

    /**
     * Standard toString() implementation.
     *
     * @return the string representation of the object
     */
    @Override
    public String toString() {
        return "Evidence{" + "name=" + name + ", source=" + source + ", value=" + value + ", confidence=" + confidence + '}';
    }
}
