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

import java.io.Serializable;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.jspecify.annotations.NonNull;

/**
 * An external reference for a vulnerability. This contains a name, URL, and a
 * source.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class Reference implements Serializable, Comparable<Reference> {

    /**
     * the serial version uid.
     */
    private static final long serialVersionUID = -3444464824563008021L;
    /**
     * The name of the reference.
     */
    private String name;
    /**
     * the url for the reference.
     */
    private String url;
    /**
     * the source of the reference.
     */
    private String source;

    /**
     * Creates a new reference.
     */
    public Reference() {
    }

    /**
     * Creates a new reference.
     *
     * @param name the reference name
     * @param source the reference source
     * @param url the reference url
     */
    public Reference(String name, String source, String url) {
        this.name = name;
        this.source = source;
        this.url = url;
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
     * Get the value of url.
     *
     * @return the value of url
     */
    public String getUrl() {
        return url;
    }

    /**
     * Set the value of url.
     *
     * @param url new value of url
     */
    public void setUrl(String url) {
        this.url = url;
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

    @Override
    public String toString() {
        return "Reference: { name='" + this.name + "', url='" + this.url + "', source='" + this.source + "' }";
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Reference)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final Reference rhs = (Reference) obj;
        return new EqualsBuilder()
                .append(source, rhs.source)
                .append(name, rhs.name)
                .append(url, rhs.url)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(5, 67)
                .append(source)
                .append(name)
                .append(url)
                .toHashCode();
    }

    /**
     * Implementation of the comparable interface.
     *
     * @param o the Reference being compared
     * @return an integer indicating the ordering of the two objects
     */
    @Override
    public int compareTo(@NonNull Reference o) {
        return new CompareToBuilder()
                .append(source, o.source)
                .append(name, o.name)
                .append(url, o.url)
                .toComparison();
    }
}
