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
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.concurrent.ThreadSafe;

/**
 * <p>
 * A utility class to extract version numbers from file names (or other strings
 * containing version numbers.</p>
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class DependencyVersionUtil {

    /**
     * Regular expression to extract version numbers from file names.
     */
    private static final Pattern RX_VERSION = Pattern.compile(
            "\\d+(\\.\\d+){1,6}([._-]?(snapshot|release|final|alpha|beta|rc$|[a-zA-Z]{1,3}[_-]?\\d{1,8}|[a-z]\\b|\\d{1,8}\\b))?",
            Pattern.CASE_INSENSITIVE);
    /**
     * Regular expression to extract a single version number without periods.
     * This is a last ditch effort just to check in case we are missing a
     * version number using the previous regex.
     */
    private static final Pattern RX_SINGLE_VERSION = Pattern.compile(
            "\\d+(\\.\\d+){0,6}([._-]?(snapshot|release|final|alpha|beta|rc$|[a-zA-Z]{1,3}[_-]?\\d{1,8}|[a-zA-Z]\\b))?");

    /**
     * Regular expression to extract the part before the version numbers if
     * there are any based on RX_VERSION. In most cases, this part represents a
     * more accurate name.
     */
    private static final Pattern RX_PRE_VERSION = Pattern.compile("^(.+)[_-](\\d+\\.\\d{1,6})+");

    /**
     * Private constructor for utility class.
     */
    private DependencyVersionUtil() {
    }

    /**
     * <p>
     * A utility class to extract version numbers from file names (or other
     * strings containing version numbers.</p>
     * <pre>
     * Example:
     * Give the file name: library-name-1.4.1r2-release.jar
     * This function would return: 1.4.1.r2</pre>
     *
     * @param text the text being analyzed
     * @return a DependencyVersion containing the version
     */
    public static DependencyVersion parseVersion(String text) {
        return parseVersion(text, false);
    }

    /**
     * <p>
     * A utility class to extract version numbers from file names (or other
     * strings containing version numbers.</p>
     * <pre>
     * Example:
     * Give the file name: library-name-1.4.1r2-release.jar
     * This function would return: 1.4.1.r2</pre>
     *
     * @param text the text being analyzed
     * @param firstMatchOnly if <code>false</code> and more then one version
     * string is found in the given text, null will be returned. Otherwise, the
     * first version found will be returned.
     * @return a DependencyVersion containing the version
     */
    public static DependencyVersion parseVersion(String text, boolean firstMatchOnly) {
        if (text == null) {
            return null;
        }
        //'-' is a special case used within the CVE entries, just include it as the version.
        if ("-".equals(text)) {
            final DependencyVersion dv = new DependencyVersion();
            final List<String> list = new ArrayList<>();
            list.add(text);
            dv.setVersionParts(list);
            return dv;
        }
        String version = null;
        Matcher matcher = RX_VERSION.matcher(text);
        if (matcher.find()) {
            version = matcher.group();
        }
        //throw away the results if there are two things that look like version numbers
        if (!firstMatchOnly && matcher.find()) {
            return null;
        }
        if (version == null) {
            matcher = RX_SINGLE_VERSION.matcher(text);
            if (matcher.find()) {
                version = matcher.group();
            } else {
                return null;
            }
            //throw away the results if there are two things that look like version numbers
            if (matcher.find()) {
                return null;
            }
        }
        if (version != null && version.endsWith("-py2") && version.length() > 4) {
            version = version.substring(0, version.length() - 4);
        }
        return new DependencyVersion(version);
    }

    /**
     * <p>
     * A utility class to extract the part before version numbers from file
     * names (or other strings containing version numbers. In most cases, this
     * part represents a more accurate name than the full file name.</p>
     * <pre>
     * Example:
     * Give the file name: library-name-1.4.1r2-release.jar
     * This function would return: library-name</pre>
     *
     * @param text the text being analyzed
     * @return the part before the version numbers if any, otherwise return the
     * text itself.
     */
    public static String parsePreVersion(String text) {
        if (parseVersion(text) == null) {
            return text;
        }

        final Matcher matcher = RX_PRE_VERSION.matcher(text);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return text;
    }
}
