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

import com.google.common.base.Suppliers;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import javax.annotation.concurrent.ThreadSafe;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * A simple PropertyType used to represent a string value that could be used as
 * a regular expression or could be case insensitive. The equals method has been
 * over-ridden so that the object will correctly compare to strings.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class PropertyType {

    //<editor-fold defaultstate="collapsed" desc="properties">
    /**
     * The value.
     */
    private final String value;
    /**
     * Whether or not the expression is a regex.
     */
    private final boolean regex;
    /**
     * Indicates case sensitivity.
     */
    private final boolean caseSensitive;

    private final Supplier<Pattern> compiledRegex = Suppliers
            .memoize(() -> isRegex() ? Pattern.compile(getValue(), isCaseSensitive() ? 0 : Pattern.CASE_INSENSITIVE) : null);

    /**
     * @param value the value of the value property
     * @param regex whether the value is a regex
     * @param caseSensitive whether the value is case-sensitive
     */
    public PropertyType(String value, boolean regex, boolean caseSensitive) {
        this.value = value;
        this.regex = regex;
        this.caseSensitive = caseSensitive;
    }

    public static PropertyType of(String value) {
        return new PropertyType(value, false, false);
    }

    public static PropertyType regex(String value) {
        return new PropertyType(value, true, false);
    }

    public static PropertyType caseSensitive(String value) {
        return new PropertyType(value, false, true);
    }

    public static PropertyType regexCaseSensitive(String value) {
        return new PropertyType(value, true, true);
    }

    /**
     * Gets the value of the value property.
     *
     * @return the value of the value property
     */
    public String getValue() {
        return value;
    }

    /**
     * Returns whether or not the value is a regex.
     *
     * @return true if the value is a regex, otherwise false
     */
    public boolean isRegex() {
        return regex;
    }

    /**
     * Gets the value of the caseSensitive property.
     *
     * @return true if the value is case-sensitive
     */
    public boolean isCaseSensitive() {
        return caseSensitive;
    }
    //</editor-fold>

    /**
     * Uses the object's properties to determine if the supplied string matches
     * the value of this property.
     *
     * @param text the String to validate
     * @return whether the text supplied is matched by the value of the property
     */
    public boolean matches(String text) {
        if (text == null) {
            return false;
        }
        if (this.regex) {
            return compiledRegex.get().matcher(text).matches();
        } else {
            if (this.caseSensitive) {
                return value.equals(text);
            } else {
                return value.equalsIgnoreCase(text);
            }
        }
    }

    //<editor-fold defaultstate="collapsed" desc="standard implementations of hashCode, equals, and toString">

    /**
     * Default implementation of hashCode.
     *
     * @return the hash code
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(3, 59)
                .append(value)
                .append(regex)
                .append(caseSensitive)
                .toHashCode();
    }

    /**
     * Default implementation of equals.
     *
     * @param obj the object to compare
     * @return whether the objects are equivalent
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof PropertyType)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final PropertyType rhs = (PropertyType) obj;
        return new EqualsBuilder()
                .append(value, rhs.value)
                .append(regex, rhs.regex)
                .append(caseSensitive, rhs.caseSensitive)
                .isEquals();
    }

    /**
     * Default implementation of toString().
     *
     * @return the string representation of the object
     */
    @Override
    public String toString() {
        return "PropertyType{" + "value=" + value + ", regex=" + regex + ", caseSensitive=" + caseSensitive + '}';
    }
    //</editor-fold>
}
