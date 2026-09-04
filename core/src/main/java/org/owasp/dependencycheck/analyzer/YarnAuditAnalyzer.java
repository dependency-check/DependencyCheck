/*
 * This file is part of dependency-check-ant.
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
 * Copyright (c) 2021 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.jspecify.annotations.NonNull;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.analyzer.exception.UnexpectedAnalysisException;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.processing.ProcessReader;
import org.semver4j.Semver;
import org.semver4j.SemverException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.exceptions.CpeValidationException;

import javax.annotation.concurrent.ThreadSafe;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.defaultIfBlank;
import static org.apache.commons.lang3.SystemUtils.getEnvironmentVariable;
import static org.owasp.dependencycheck.utils.FileUtils.existsWithContent;

@ThreadSafe
public class YarnAuditAnalyzer extends AbstractNpmAnalyzer {

    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(YarnAuditAnalyzer.class);

    /**
     * Minimum Yarn version supported. Only in Yarn v4 was support for the newer npm audit bulk API added, however 2.4.0
     * added support for `yarn npm audit` via the legacy API (deprecated, likely decommissioned in 2026). package.jsons
     * or environments implying a version lower than this will be ignored.
     */
    private static final String YARN_VERSION_MIN = "2.4.0";

    /**
     * The file name to scan.
     */
    public static final String YARN_PACKAGE_LOCK = "yarn.lock";
    static final String YARN_ENV_IGNORE_PATH = "YARN_IGNORE_PATH";
    static final String YARN_ENV_ENABLE_TELEMETRY = "YARN_ENABLE_TELEMETRY";

    /**
     * Filter that detects files named "yarn.lock"
     */
    private static final FileFilter LOCK_FILE_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(YARN_PACKAGE_LOCK).build();

    /**
     * The path to the `yarn` executable.
     */
    private String yarnPath;

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_YARN_AUDIT_ENABLED;
    }

    @Override
    protected FileFilter getFileFilter() {
        return LOCK_FILE_FILTER;
    }

    @Override
    public String getName() {
        return "Yarn Audit Analyzer";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINDING_ANALYSIS;
    }

    /**
     * Determines the Yarn major version implied by the metadata in the passed directory.
     *
     * @param dependencyDirectory The directory containing the lockfile and/or package.json
     * @return the yarn version detected
     */
    private Semver getYarnVersion(File dependencyDirectory) {
        List<String> args = List.of(yarnPath, "--version");
        final ProcessBuilder builder = createYarnBuilder(dependencyDirectory, args);
        try {
            final Process process = builder.start();
            try (ProcessReader processReader = new ProcessReader(process)) {
                processReader.readAll();
                final int exitValue = process.waitFor();
                final var yarnVersion = StringUtils.trimToEmpty(processReader.getOutput());
                if (exitValue != 0) {
                    throw new IllegalStateException(String.format("Unable to determine yarn version, unexpected response (exit value %s, output: %s, error: %s)", exitValue, yarnVersion, processReader.getError()));
                }
                if (StringUtils.isBlank(yarnVersion)) {
                    throw new IllegalStateException("Unable to determine yarn version, blank output.");
                }
                return Semver.coerce(yarnVersion);
            }
        }  catch (SemverException e) {
            throw new IllegalStateException("Invalid version string format", e);
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to determine yarn version.", ex);
        }
    }

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException if there's an error during initialization
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        super.prepareFileTypeAnalyzer(engine);
        if (!isEnabled()) {
            LOGGER.debug("{} Analyzer is disabled skipping yarn executable check", getName());
            return;
        }
        try {
            cacheYarnCommandPath();
            getYarnVersion(new File("."));
        } catch (Exception ex){
            this.setEnabled(false);
            LOGGER.warn("The {} has been disabled after failing to find yarn. Yarn executable was not " +
                    "found or received a non-zero exit value: {}", getName(), ex.getMessage());
            throw new InitializationException("Unable to determine yarn executable to use.", ex);
        }
    }

    /**
     * Attempts to determine and cache the path to `yarn`.
     */
    private void cacheYarnCommandPath() {
        String value = getSettings().getString(Settings.KEYS.ANALYZER_YARN_PATH);
        if (value == null || value.isBlank()) {
            value = "yarn";
        } else {
            File fileValue = new File(value);
            if (fileValue.isFile()) {
                value = fileValue.getAbsolutePath();
            } else {
                LOGGER.warn("Provided path to `yarn` executable is invalid; defaulting to `yarn`.");
                value = "yarn";
            }
        }

        yarnPath = value;
    }

    /**
     * Workaround 64k limitation of InputStream, redirect stdout to a file that we will read later
     * instead of reading directly stdout from Process's InputStream which is topped at 64k
     *
     * @param builder a reference to the process builder
     * @return returns the standard out from the process
     */
    private String startAndReadStdoutToString(ProcessBuilder builder) throws AnalysisException {
        try {
            final File tmpFile = getSettings().getTempFile("yarn_audit", "json");
            builder.redirectOutput(tmpFile);
            final Process process = builder.start();
            try (ProcessReader processReader = new ProcessReader(process)) {
                processReader.readAll();
                final String errOutput = processReader.getError();

                if (!StringUtils.isBlank(errOutput)) {
                    LOGGER.debug("Process Error Out: {}", errOutput);
                    LOGGER.debug("Process Out: {}", processReader.getOutput());
                }
                return Files.readString(tmpFile.toPath());
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new AnalysisException("Yarn audit process was interrupted.", ex);
            }
        } catch (IOException ioe) {
            throw new AnalysisException("yarn audit failure; this error can be ignored if you are not analyzing projects with a yarn lockfile.", ioe);
        }
    }

    /**
     * Analyzes the yarn lock file to determine vulnerable dependencies using the Yarn CLI to talk to the npm audit
     * bulk API and parsed advisories in simple return format.
     *
     * @param dependency the yarn lock file
     * @param engine the analysis engine
     * @throws AnalysisException thrown if there is an error analyzing the file
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (dependency.getDisplayFileName().equals(dependency.getFileName())) {
            engine.removeDependency(dependency);
        }
        final File packageLock = dependency.getActualFile();
        if (!existsWithContent(packageLock) || !shouldProcess(packageLock)) {
            return;
        }
        File dependencyDirectory = getDependencyDirectory(packageLock);
        final var yarnVersion = getYarnVersion(dependencyDirectory);
        if (yarnVersion.isLowerThan(YARN_VERSION_MIN)) {
            LOGGER.warn("Yarn dependency skipped: {} - Yarn v{} (prior to v{}) is not supported.", dependency.getActualFile(), yarnVersion, YARN_VERSION_MIN);
            return;
        }

        LOGGER.info("Analyzing using Yarn Berry ({}) audit for {}", yarnVersion, dependency.getActualFilePath());
        try {
            final var skipDevDependencies = getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_SKIPDEV, false);
            final var advisoryJsons = fetchYarnAdvisories(dependency, skipDevDependencies);
            List<Advisory> advisories = parseAdvisoryJsons(advisoryJsons);
            processResults(advisories, engine, dependency, new HashSetValuedHashMap<>());
        } catch (JSONException e) {
            throw new AnalysisException("Failed to parse the advisories from `yarn npm audit` (YarnAuditAnalyzer).", e);
        } catch (CpeValidationException e) {
            throw new UnexpectedAnalysisException(e);
        }
    }

    private static File getDependencyDirectory(File lockFile) {
        final File folder = lockFile.getParentFile();
        if (!folder.isDirectory()) {
            throw new IllegalArgumentException(String.format("%s should have been a directory.", folder.getAbsolutePath()));
        }
        return folder;
    }

    private List<JSONObject> fetchYarnAdvisories(Dependency dependency, boolean skipDevDependencies) throws AnalysisException {
        final List<String> args = new ArrayList<>();

        args.add(yarnPath);
        args.add("npm");
        args.add("audit");
        if (skipDevDependencies) {
            args.add("--environment");
            args.add("production");
        }
        args.add("--all");
        args.add("--recursive");
        args.add("--no-deprecations");
        args.add("--json");
        final String advisoriesJsons = startAndReadStdoutToString(createYarnBuilder(getDependencyDirectory(dependency.getActualFile()), args));

        LOGGER.debug("Advisories JSON: {}", advisoriesJsons);
        return advisoriesJsons.lines()
                .filter(s -> !s.isBlank())
                .map(JSONObject::new)
                .collect(Collectors.toList());
    }

    private static @NonNull ProcessBuilder createYarnBuilder(File dependencyDirectory, List<String> args) {
        final ProcessBuilder builder = new ProcessBuilder(args).directory(dependencyDirectory);

        builder.environment().putAll(Map.of(
                // Default to disable use of yarnPath
                YARN_ENV_IGNORE_PATH, defaultIfBlank(getEnvironmentVariable(YARN_ENV_IGNORE_PATH, null), "true"),
                // Force disable telemetry
                YARN_ENV_ENABLE_TELEMETRY, "false"
        ));
        return builder;
    }

    private static List<Advisory> parseAdvisoryJsons(List<JSONObject> advisoryJsons) throws JSONException {
        final List<Advisory> advisories = new ArrayList<>();
        for (JSONObject advisoryJson : advisoryJsons) {
            final var advisory = new Advisory();
            final var object = advisoryJson.getJSONObject("children");
            final var moduleName = advisoryJson.optString("value", null);
            final var id = object.get("ID");
            final var url = object.optString("URL", null);
            final var ghsaId = extractGhsaId(url);
            final var issue = object.optString("Issue", null);
            final var severity = object.optString("Severity", null);
            final var vulnerableVersions = object.optString("Vulnerable Versions", null);
            final var treeVersions = object.optJSONArray("Tree Versions");
            final var treeVersionsLength = treeVersions == null ? 0 : treeVersions.length();
            final var versions = new ArrayList<String>();
            for (int i = 0; i < treeVersionsLength; i++) {
                versions.add(treeVersions.getString(i));
            }
            if (versions.isEmpty()) {
                versions.add(null);
            }
            for (String version : versions) {
                advisory.setGhsaId(ghsaId);
                advisory.setTitle(issue);
                advisory.setOverview("URL:" + url + "ID: " + id);
                advisory.setSeverity(severity);
                advisory.setVulnerableVersions(vulnerableVersions);
                advisory.setModuleName(moduleName);
                advisory.setVersion(version);
                advisory.setCwes(new ArrayList<>());
                advisories.add(advisory);
            }
        }
        return advisories;
    }

    private static String extractGhsaId(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        final int lastSlashIndex = url.lastIndexOf('/');
        if (lastSlashIndex == -1 || lastSlashIndex == url.length() - 1) {
            return null;
        }
        return url.substring(lastSlashIndex + 1);
    }
}
