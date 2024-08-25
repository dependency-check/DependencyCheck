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
package org.owasp.dependencycheck.utils;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.concurrent.NotThreadSafe;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.jetbrains.annotations.NotNull;

/**
 * <p>
 * Simple object to track the parts of a version number. The parts are contained
 * in a List such that version 1.2.3 will be stored as:  <code>versionParts[0] = 1;
 * versionParts[1] = 2;
 * versionParts[2] = 3;
 * </code></p>
 * <p>
 * Note, the parser contained in this class expects the version numbers to be
 * separated by periods. If a different separator is used the parser will likely
 * fail.</p>
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class DependencyVersion implements Iterable<String>, Comparable<DependencyVersion> {

    /**
     * A list of the version parts.
     */
    private List<String> versionParts;

    /**
     * Constructor for a empty DependencyVersion.
     */
    public DependencyVersion() {
    }

    /**
     * Constructor for a DependencyVersion that will parse a version string.
     * <b>Note</b>, this should only be used when the version passed in is
     * already known to be a well formatted version number. Otherwise,
     * DependencyVersionUtil.parseVersion() should be used instead.
     *
     * @param version the well formatted version number to parse
     */
    public DependencyVersion(String version) {
        parseVersion(version);
    }

    /**
     * Parses a version string into its sub parts: major, minor, revision,
     * build, etc. <b>Note</b>, this should only be used to parse something that
     * is already known to be a version number.
     *
     * @param version the version string to parse
     */
    public final void parseVersion(String version) {
        versionParts = new ArrayList<>();
        if (version != null) {
            final Pattern rx = Pattern
                    .compile("(\\d{1,100}[a-z]{1,3}$|[a-z]{1,3}[_-]?\\d{1,100}|\\d{1,100}|(rc|release|snapshot|beta|alpha)$)",
                            Pattern.CASE_INSENSITIVE);
            final Matcher matcher = rx.matcher(version.toLowerCase());
            while (matcher.find()) {
                versionParts.add(matcher.group());
            }
            if (versionParts.isEmpty()) {
                versionParts.add(version);
            }
        }
    }

    /**
     * Get the value of versionParts.
     *
     * @return the value of versionParts
     */
    public List<String> getVersionParts() {
        return versionParts;
    }

    /**
     * Set the value of versionParts.
     *
     * @param versionParts new value of versionParts
     */
    public void setVersionParts(List<String> versionParts) {
        this.versionParts = versionParts;
    }

    /**
     * Retrieves an iterator for the version parts.
     *
     * @return an iterator for the version parts
     */
    @NotNull
    @Override
    public Iterator<String> iterator() {
        return versionParts.iterator();
    }

    /**
     * Reconstructs the version string from the split version parts.
     *
     * @return a string representing the version.
     */
    @Override
    public String toString() {
        return StringUtils.join(versionParts, '.');
    }

    /**
     * Compares the equality of this object to the one passed in as a parameter.
     *
     * @param obj the object to compare equality
     * @return returns true only if the two objects are equal, otherwise false
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof DependencyVersion)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final DependencyVersion other = (DependencyVersion) obj;
        final int minVersionMatchLength = Math.min(this.versionParts.size(), other.versionParts.size());
        final int maxVersionMatchLength = Math.max(this.versionParts.size(), other.versionParts.size());

        if (minVersionMatchLength == 1 && maxVersionMatchLength >= 3) {
            return false;
        }

        //TODO steal better version of code from compareTo
        for (int i = 0; i < minVersionMatchLength; i++) {
            final String thisPart = this.versionParts.get(i);
            final String otherPart = other.versionParts.get(i);
            if (!thisPart.equals(otherPart)) {
                return false;
            }
        }
        if (this.versionParts.size() > minVersionMatchLength) {
            for (int i = minVersionMatchLength; i < this.versionParts.size(); i++) {
                if (!"0".equals(this.versionParts.get(i))) {
                    return false;
                }
            }
        }

        if (other.versionParts.size() > minVersionMatchLength) {
            for (int i = minVersionMatchLength; i < other.versionParts.size(); i++) {
                if (!"0".equals(other.versionParts.get(i))) {
                    return false;
                }
            }
        }

        /*
         *  if (this.versionParts != other.versionParts && (this.versionParts == null || !this.versionParts.equals(other.versionParts))) {
         *      return false;
         *  }
         */
        return true;
    }

    /**
     * Calculates the hashCode for this object.
     *
     * @return the hashCode
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(5, 71)
                .append(versionParts)
                .toHashCode();
    }

    /**
     * Determines if the three most major major version parts are identical. For
     * instances, if version 1.2.3.4 was compared to 1.2.3 this function would
     * return true.
     *
     * @param version the version number to compare
     * @return true if the first three major parts of the version are identical
     */
    public boolean matchesAtLeastThreeLevels(DependencyVersion version) {
        if (version == null) {
            return false;
        }
        if (Math.abs(this.versionParts.size() - version.versionParts.size()) >= 3) {
            return false;
        }

        final int max = Math.min(this.versionParts.size(), version.versionParts.size());

        boolean ret = true;
        for (int i = 0; i < max; i++) {
            final String thisVersion = this.versionParts.get(i);
            final String otherVersion = version.getVersionParts().get(i);
            if (i >= 3) {
                if (thisVersion.compareToIgnoreCase(otherVersion) >= 0) {
                    ret = false;
                    break;
                }
            } else if (!thisVersion.equals(otherVersion)) {
                ret = false;
                break;
            }
        }

        return ret;
    }

    @Override
    public int compareTo(@NotNull DependencyVersion version) {
        if (version == null) {
            return 1;
        }
        final List<String> left = this.getVersionParts();
        final List<String> right = version.getVersionParts();
        final int max = Math.min(left.size(), right.size());

        for (int i = 0; i < max; i++) {
            final String lStr = left.get(i);
            final String rStr = right.get(i);
            if (lStr.equals(rStr)) {
                continue;
            }
            try {
                final int l = Integer.parseInt(lStr);
                final int r = Integer.parseInt(rStr);
                if (l < r) {
                    return -1;
                } else if (l > r) {
                    return 1;
                }
            } catch (NumberFormatException ex) {
                final int comp = left.get(i).compareTo(right.get(i));
                if (comp < 0) {
                    return -1;
                } else if (comp > 0) {
                    return 1;
                }
            }
        }
        return Integer.compare(left.size(), right.size());
    }
}
