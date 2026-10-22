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
 * Copyright (c) 2020 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvd.ecosystem;

import java.util.Locale;

import org.owasp.dependencycheck.utils.Settings;

/**
 * Collection of the standard ecosystems for dependency-check.
 *
 * @author Jeremy Long
 */
public final class Ecosystem {

    /**
     * The Ruby ecosystem.
     */
    public static final String RUBY = "ruby";
    /**
     * The dotnet ecosystem.
     */
    public static final String DOTNET = "dotnet";
    /**
     * The iOS ecosystem.
     */
    public static final String IOS = "ios";
    /**
     * The PHP ecosystem.
     */
    public static final String PHP = "php";
    /**
     * The Golang ecosystem.
     */
    public static final String GOLANG = "golang";
    /**
     * The Java ecosystem.
     */
    public static final String JAVA = "java";
    /**
     * The native ecosystem.
     */
    public static final String NATIVE = "native";
    /**
     * The Python ecosystem.
     */
    public static final String PYTHON = "python";
    /**
     * The JavaScript ecosystem.
     */
    public static final String JAVASCRIPT = "js";
    /**
     * The Node.JS ecosystem.
     */
    public static final String NODEJS = "nodejs";
    /**
     * The rust ecosystem.
     */
    public static final String RUST = "rust";
    /**
     * The rust ecosystem.
     */
    public static final String COLDFUSION = "coldfusion";
    /**
     * The Perl ecosystem.
     */
    public static final String PERL = "perl";
    /**
     * The Elixir ecosystem.
     */
    public static final String ELIXIR = "exlixir";

    /**
     * The Dart ecosystem.
     */
    public static final String DART = "dart";

    /**
     * A reference to the ODC settings.
     */
    private final Settings settings;
    /**
     * The lucene default query size.
     */
    private final int defaultQuerySize;

    /**
     * Instantiates the ecosystem utility class.
     *
     * @param settings the ODC configuration
     */
    public Ecosystem(Settings settings) {
        this.settings = settings;
        this.defaultQuerySize = settings.getInt(Settings.KEYS.MAX_QUERY_SIZE_DEFAULT, 100);
    }

    /**
     * Returns the max query result size for the Lucene search for each
     * ecosystem.
     *
     * @param ecosystem the ecosystem
     * @return the max query result size
     */
    public int getLuceneMaxQueryLimitFor(String ecosystem) {
        return settings.getInt(Settings.KEYS.MAX_QUERY_SIZE_PREFIX + ecosystem, defaultQuerySize);
    }

    /**
     * Returns ecosystem a targetsw may belong to
     *
     * @param targetsw the targetsw
     * @return Ecosystem the target software may belong to or Null otherwise.
     */

    public static String fromTargetSoftware(String targetSw) {
        if (targetSw == null) {
            return null;
        }

        final String normalized = targetSw.trim()
                .toLowerCase(Locale.ROOT)
                .replace("_", "")
                .replace("-", "")
                .replace(".", "");

        switch (normalized) {
            case "nodejs":
            case "npm":
                return NODEJS;

            case "java":
            case "jvm":
                return JAVA;

            case "python":
            case "pypi":
                return PYTHON;

            case "php":
            case "composer":
                return PHP;

            case "go":
            case "golang":
                return GOLANG;

            case "dotnet":
            case "nuget":
                return DOTNET;

            case "cargo":
            case "rust":
                return RUST;

            case "ruby":
            case "rubygems":
                return RUBY;

            case "ios":
            case "iphoneos":
                return IOS;

            case "native":
                return NATIVE;

            case "coldfusion":
            case "cfml":
                return COLDFUSION;

            case "perl":
                return PERL;

            case "elixir":
                return ELIXIR;

            case "dart":
                return DART;

            default:
                return null;
        }
    }

    /**
     * Determines if ecosystem and targetsw are
     * compatible based on runtime information.
     *
     *
     * @param ecosystem      the dependency ecosystem
     * @param targetSoftware the NVD target software
     * @return false only when both runtimes are recognized and differ
     */
    public static boolean isCompatibleWithTargetSoftware(
            String ecosystem, String targetSoftware) {

        final String dependencyRuntime = fromTargetSoftware(ecosystem);
        final String targetRuntime = fromTargetSoftware(targetSoftware);

        return dependencyRuntime == null
                || targetRuntime == null
                || dependencyRuntime.equals(targetRuntime);
    }
}
