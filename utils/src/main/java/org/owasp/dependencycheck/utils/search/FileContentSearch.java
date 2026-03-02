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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils.search;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Utility for searching files.
 *
 * @author Jeremy Long
 * @version $Id: $Id
 */
public final class FileContentSearch {

    /**
     * Private constructor for a utility class.
     */
    private FileContentSearch() {
        //empty constructor for utility class.
    }

    /**
     * Determines if the given file contains the given regular expression.
     *
     * @param file the file to test
     * @param pattern the pattern used to test the file
     * @return <code>true</code> if the regular expression matches the file
     * content; otherwise <code>false</code>
     * @throws java.io.IOException thrown if there is an error reading the file
     */
    public static boolean contains(File file, String pattern) throws IOException {
        try (Scanner fileScanner = new Scanner(file, UTF_8)) {
            final Pattern regex = Pattern.compile(pattern);
            if (fileScanner.findWithinHorizon(regex, 0) != null) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determines if the given file contains the given regular expressions.
     *
     * @param file the file to test
     * @param patterns the array of patterns used to test the file
     * @return <code>true</code> if one of the regular expressions matches the
     * file content; otherwise <code>false</code>
     * @throws java.io.IOException thrown if there is an error reading the file
     */
    public static boolean contains(File file, String[] patterns) throws IOException {
        final List<Pattern> regexes = new ArrayList<>();
        for (String pattern : patterns) {
            regexes.add(Pattern.compile(pattern));
        }
        try (Scanner fileScanner = new Scanner(file, UTF_8)) {
            return regexes.stream().anyMatch((regex) -> (fileScanner.findWithinHorizon(regex, 0) != null));
        }
    }
}
