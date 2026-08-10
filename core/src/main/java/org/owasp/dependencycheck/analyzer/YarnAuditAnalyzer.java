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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.owasp.dependencycheck.utils.FileUtils.existsWithContent;

@ThreadSafe
public class YarnAuditAnalyzer extends AbstractNpmAnalyzer {

    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(YarnAuditAnalyzer.class);

    private static final int YARN_BERRY_MAJOR_VERSION_MIN = 2;

    /**
     * The file name to scan.
     */
    public static final String YARN_PACKAGE_LOCK = "yarn.lock";

    /**
     * Filter that detects files named "yarn.lock"
     */
    private static final FileFilter LOCK_FILE_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(YARN_PACKAGE_LOCK).build();

    /**
     * The path to the `yarn` executable.
     */
    private String yarnPath;

    private static final String PACKAGE_JSON_FILE_NAME = "package.json";

    private static final String NODE_OPTIONS_ENV = "NODE_OPTIONS";
    private static final String YARN_IGNORE_PATH_ENV = "YARN_IGNORE_PATH";
    private static final String COREPACK_EXECUTABLE = "corepack";
    private static final Pattern PACKAGE_MANAGER_PATTERN = Pattern.compile("\\\"packageManager\\\"\\s*:\\s*\\\"yarn@([^\\\"]+)\\\"");

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
        final ProcessBuilder builder = new ProcessBuilder(args);
        builder.directory(dependencyDirectory);
        builder.environment().remove(NODE_OPTIONS_ENV);
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
                final Semver runtimeVersion = Semver.coerce(yarnVersion);
                final String declaredPackageManager = readDeclaredYarnPackageManagerVersion(dependencyDirectory);
                if (declaredPackageManager == null) {
                    return runtimeVersion;
                }

                final Semver declaredVersion = Semver.coerce(declaredPackageManager);
                if (declaredVersion.getMajor() < YARN_BERRY_MAJOR_VERSION_MIN) {
                    // Respect fixture/package intent even if an ancestor config forces a different runtime.
                    return declaredVersion;
                }

                if (runtimeVersion.compareTo(declaredVersion) < 0) {
                    throw new IllegalStateException(String.format(
                            "Unable to determine yarn version, unexpected response (exit value 1, output: %s, error: Declared packageManager yarn@%s requires a newer yarn runtime)",
                            runtimeVersion,
                            declaredPackageManager
                    ));
                }
                return runtimeVersion;
            }
        }  catch (SemverException e) {
            throw new IllegalStateException("Invalid version string format", e);
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to determine yarn version.", ex);
        }
    }

    private String readDeclaredYarnPackageManagerVersion(File dependencyDirectory) {
        final Path packageJsonPath = dependencyDirectory.toPath().resolve(PACKAGE_JSON_FILE_NAME);
        if (!Files.isRegularFile(packageJsonPath)) {
            return null;
        }
        try {
            final String packageJsonContent = Files.readString(packageJsonPath);
            final Matcher matcher = PACKAGE_MANAGER_PATTERN.matcher(packageJsonContent);
            if (!matcher.find()) {
                return null;
            }
            return StringUtils.trimToNull(matcher.group(1));
        } catch (IOException e) {
            LOGGER.debug("Unable to read package manager from {}", packageJsonPath, e);
            return null;
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
    private ProcessOutput startAndReadProcessOutput(ProcessBuilder builder) throws AnalysisException {
        try {
            final File tmpFile = getSettings().getTempFile("yarn_audit", "json");
            builder.redirectOutput(tmpFile);
            final Process process = builder.start();
            try (ProcessReader processReader = new ProcessReader(process)) {
                processReader.readAll();
                final int exitValue = process.waitFor();
                final String errOutput = processReader.getError();
                final String output = Files.readString(tmpFile.toPath());

                if (!StringUtils.isBlank(errOutput)) {
                    LOGGER.debug("Process Error Out: {}", errOutput);
                    LOGGER.debug("Process Out: {}", output);
                }
                return new ProcessOutput(output, errOutput, exitValue);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new AnalysisException("Yarn audit process was interrupted.", ex);
            }
        } catch (IOException ioe) {
            throw new AnalysisException("yarn audit failure; this error can be ignored if you are not analyzing projects with a yarn lockfile.", ioe);
        }
    }

    private static final class ProcessOutput {
        private final String output;
        private final String error;
        private final int exitValue;

        private ProcessOutput(String output, String error, int exitValue) {
            this.output = output;
            this.error = error;
            this.exitValue = exitValue;
        }
    }

    /**
     * Analyzes the yarn lock file to determine vulnerable dependencies. Uses
     * yarn audit --offline to generate the payload to be sent to the NPM API.
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
        if (yarnVersion.getMajor() < YARN_BERRY_MAJOR_VERSION_MIN) {
            LOGGER.warn("Yarn dependency skipped: {} - Yarn Classic (v{}) is not supported.", dependency.getActualFile(), yarnVersion);
            return;
        }

        LOGGER.info("Analyzing using Yarn Berry ({}) audit for {}", yarnVersion, dependency.getActualFilePath());
        try {
            final var skipDevDependencies = getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_SKIPDEV, false);
            final var advisoryJsons = fetchYarnAdvisories(dependency, skipDevDependencies);
            List<Advisory> advisories = parseAdvisoryJsons(advisoryJsons);
            processResults(advisories, engine, dependency, new HashSetValuedHashMap<>());
        } catch (JSONException e) {
            throw new AnalysisException("Failed to parse the response from NPM Audit API (YarnAuditAnalyzer).", e);
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
        final File dependencyDirectory = getDependencyDirectory(dependency.getActualFile());
        final String declaredPackageManager = readDeclaredYarnPackageManagerVersion(dependencyDirectory);
        final Semver declaredVersion = declaredPackageManager == null ? null : Semver.coerce(declaredPackageManager);
        final boolean useCorepack = declaredVersion != null && declaredVersion.getMajor() >= YARN_BERRY_MAJOR_VERSION_MIN;

        if (useCorepack) {
            args.add(COREPACK_EXECUTABLE);
            args.add("yarn");
        } else {
            args.add(yarnPath);
        }
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
        final ProcessBuilder builder = new ProcessBuilder(args);
        builder.directory(dependencyDirectory);
        builder.environment().remove(NODE_OPTIONS_ENV);
        if (useCorepack) {
            builder.environment().put(YARN_IGNORE_PATH_ENV, "1");
        }

        final ProcessOutput processOutput = startAndReadProcessOutput(builder);
        final String advisoriesJsons = processOutput.output;

        LOGGER.debug("Advisories JSON: {}", advisoriesJsons);
        final String[] advisoriesJsonArray = Stream.of(advisoriesJsons.split("\n"))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .filter(s -> s.startsWith("{") && s.endsWith("}"))
                .toArray(String[]::new);
        try {
            final List<JSONObject> advisories = new ArrayList<>();
            for (String advisoriesJson : advisoriesJsonArray) {
                final JSONObject advisoryCandidate = new JSONObject(advisoriesJson);
                if (advisoryCandidate.has("children") && advisoryCandidate.opt("children") instanceof JSONObject) {
                    advisories.add(advisoryCandidate);
                }
            }

                if (processOutput.exitValue != 0 && advisories.isEmpty()) {
                throw new AnalysisException(String.format(
                        "Yarn audit command failed (exit value %s): %s",
                        processOutput.exitValue,
                        StringUtils.defaultIfBlank(processOutput.error, advisoriesJsons)
                ));
            }

            return advisories;
        } catch (JSONException e) {
            throw new AnalysisException("Failed to parse the response from NPM Audit API (YarnAuditAnalyzer).", e);
        }
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
