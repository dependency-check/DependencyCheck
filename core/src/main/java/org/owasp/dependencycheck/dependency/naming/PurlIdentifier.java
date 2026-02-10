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

import com.github.packageurl.MalformedPackageURLException;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.jspecify.annotations.NonNull;
import org.owasp.dependencycheck.dependency.Confidence;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

/**
 * The Package-URL Identifier implementation.
 *
 * @author Jeremy Long
 */
public class PurlIdentifier implements Identifier {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 8371122848306175579L;

    /**
     * The PackageURL identifier.
     */
    private final PackageURL purl;
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
     * Constructs a new Package-URL identifier.
     *
     * @param purl the Package-URL object
     * @param confidence the confidence that the identifier is correct for the
     * given dependency
     */
    public PurlIdentifier(PackageURL purl, Confidence confidence) {
        this.purl = purl;
        this.confidence = confidence;
        this.url = null;
    }

    /**
     * Constructs a new Package-URL identifier.
     *
     * @param purl the Package-URL object
     * @param url the URL for the identifier
     * @param confidence the confidence that the identifier is correct for the
     * given dependency
     */
    public PurlIdentifier(PackageURL purl, String url, Confidence confidence) {
        this.purl = purl;
        this.confidence = confidence;
        this.url = url;
    }

    /**
     * Constructs a new Package-URL identifier.
     *
     * @param type the type of package-URL
     * @param name the name
     * @param version the version
     * @param confidence the confidence that the identifier is correct for the
     * given dependency
     * @throws MalformedPackageURLException thrown if the type, name space,
     * name, and version cannot be converted into a package-URL
     */
    public PurlIdentifier(String type, String name, String version, Confidence confidence) throws MalformedPackageURLException {
        this.purl = PackageURLBuilder.aPackageURL().withType(type).withName(name)
                .withVersion(version).build();
        this.confidence = confidence;
    }

    /**
     * Constructs a new Package-URL identifier.
     *
     * @param type the type of package-URL
     * @param namespace the name space
     * @param name the name
     * @param version the version
     * @param confidence the confidence that the identifier is correct for the
     * given dependency
     * @throws MalformedPackageURLException thrown if the type, name space,
     * name, and version cannot be converted into a package-URL
     */
    public PurlIdentifier(String type, String namespace, String name, String version, Confidence confidence) throws MalformedPackageURLException {
        this.purl = PackageURLBuilder.aPackageURL().withType(type).withNamespace(namespace).withName(name)
                .withVersion(version).build();
        this.confidence = confidence;
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

    /**
     * Returns the CPE 2.3 formatted string.
     *
     * @return the CPE 2.3 formatted string
     */
    @Override
    public String toString() {
        return purl.canonicalize();
    }

    @Override
    public String getValue() {
        return purl.canonicalize();
    }

    /**
     * Returns the Package URL name space.
     *
     * @return the Package URL name space
     */
    public String getNamespace() {
        return purl.getNamespace();
    }

    /**
     * Returns the Package URL name.
     *
     * @see com.github.packageurl.PackageURL#getName()
     * @return the Package URL name.
     */
    public String getName() {
        return purl.getName();
    }

    /**
     * Returns the Package URL version.
     *
     * @see com.github.packageurl.PackageURL#getVersion()
     * @return the Package URL name.
     */
    public String getVersion() {
        return purl.getVersion();
    }

    /**
     * Returns the GAV representation of the Package URL as utilized in gradle
     * builds.
     *
     * @return the GAV representation of the Package URL
     */
    public String toGav() {
        if (purl.getNamespace() != null && purl.getVersion() != null) {
            return String.format("%s:%s:%s", purl.getNamespace(), purl.getName(), purl.getVersion());
        }
        return null;
    }

    @Override
    public int compareTo(@NonNull Identifier o) {
        if (o instanceof PurlIdentifier) {
            final PurlIdentifier other = (PurlIdentifier) o;
            return new CompareToBuilder()
                    //todo update package url implementation to implement compare..
                    .append(this.purl.canonicalize(), other.purl.canonicalize())
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

    @Override
    public int hashCode() {
        return new HashCodeBuilder(93, 187)
                .append(this.purl)
                .append(this.confidence)
                .append(this.url)
                .append(this.notes)
                .toHashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof PurlIdentifier)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final PurlIdentifier other = (PurlIdentifier) obj;
        return new EqualsBuilder().append(purl, other.purl)
                .append(this.confidence, other.confidence)
                .append(this.url, other.url)
                .append(this.notes, other.notes)
                .isEquals();
    }
}
