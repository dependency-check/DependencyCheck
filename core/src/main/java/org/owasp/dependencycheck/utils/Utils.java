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
 * Copyright (c) 2022 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Jeremy Long
 */
public final class Utils {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);

    /**
     * Empty constructor for utility class.
     */
    private Utils() {
    }

    /**
     * Returns the Java major version as a whole number.
     *
     * @return the Java major version as a whole number
     */
    public static int getJavaVersion() {
        String version = System.getProperty("java.specification.version");
        if (version.startsWith("1.")) {
            version = version.substring(2, 3);
        } else {
            final int dot = version.indexOf(".");
            if (dot != -1) {
                version = version.substring(0, dot);
            }
        }
        return Integer.parseInt(version);
    }

    /**
     * Returns the update version from the Java runtime.
     *
     * @return the update version
     */
    public static int getJavaUpdateVersion() {
        //"1.8.0_144" "11.0.2+9" "17.0.8.1"
        final String runtimeVersion = System.getProperty("java.version");
        return parseUpdate(runtimeVersion);
    }

    /**
     * Parses the update version from the runtime version.
     *
     * @param runtimeVersion the runtime version
     * @return the update version
     */
    protected static int parseUpdate(String runtimeVersion) {
        LOGGER.debug(runtimeVersion);
        try {
            final String[] parts = runtimeVersion.split("\\.");
            if (parts.length == 4 && isNumeric(parts)) {
                return Integer.parseInt(parts[2]);
            }
            int pos = runtimeVersion.indexOf('_');
            if (pos <= 0) {
                pos = runtimeVersion.lastIndexOf('.');
                if (pos <= 0) {
                    //unexpected java version - return 0
                    return 0;
                }
            }
            int end = runtimeVersion.indexOf('+', pos);
            if (end < 0) {
                end = runtimeVersion.indexOf('-', pos);
            }
            if (end > pos) {
                return Integer.parseInt(runtimeVersion.substring(pos + 1, end));
            }
            return Integer.parseInt(runtimeVersion.substring(pos + 1));
        } catch (NumberFormatException nfe) {
            // If the update version is not available, return 0
            return 0;
        }
    }

    /**
     * Determines if all parts of the string array are numeric.
     *
     * @param parts the strings to check
     * @return true if all of the strings in the array are numeric; otherwise
     * false
     */
    private static boolean isNumeric(String[] parts) {
        for (String i : parts) {
            if (!StringUtils.isNumeric(i)) {
                return false;
            }
        }
        return true;
    }
}
