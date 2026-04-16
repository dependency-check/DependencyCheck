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

import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.jspecify.annotations.NonNull;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.analyzer.exception.SearchException;
import org.owasp.dependencycheck.analyzer.exception.UnexpectedAnalysisException;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.data.nodeaudit.NpmAuditParser;
import org.owasp.dependencycheck.data.nodeaudit.NpmAuditV2Parser;
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
import java.util.stream.Stream;

@ThreadSafe
public class YarnAuditAnalyzer extends AbstractNpmAnalyzer {

    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(YarnAuditAnalyzer.class);

    /**
     * The major version of the Yarn Classic CLI.
     */
    private static final int YARN_CLASSIC_MAJOR_VERSION = 1;

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

    /**
     * The path to the `npm` executable.
     */
    private String npmPath;

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
            cacheNpmCommandPath();
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
     * Attempts to determine and cache the path to `npm`.
     */
    private void cacheNpmCommandPath() {
        String value = getSettings().getString(Settings.KEYS.ANALYZER_NPM_PATH);
        if (value == null || value.isBlank()) {
            value = "npm";
        } else {
            File fileValue = new File(value);
            if (fileValue.isFile()) {
                value = fileValue.getAbsolutePath();
            } else {
                LOGGER.warn("Provided path to `npm` executable is invalid; defaulting to `npm`.");
                value = "npm";
            }
        }
        npmPath = value;
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
                    LOGGER.debug("Process error output: {}", errOutput);
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
        if (!packageLock.isFile() || packageLock.length() == 0 || !shouldProcess(packageLock)) {
            return;
        }
        File dependencyDirectory = getDependencyDirectory(packageLock);
        final var yarnVersion = getYarnVersion(dependencyDirectory);
        final List<Advisory> advisories;
        final MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        if (YARN_CLASSIC_MAJOR_VERSION < yarnVersion.getMajor()) {
            LOGGER.info("Analyzing using Yarn Berry ({}) audit for {}", yarnVersion, dependency.getActualFilePath());
            advisories = analyzePackageWithYarnBerry(dependency);
        } else {
            LOGGER.info("Analyzing using Yarn Classic ({}) audit for {}", yarnVersion, dependency.getActualFilePath());
            advisories = analyzePackageWithYarnClassic(packageLock, dependency);
        }
        try {
            processResults(advisories, engine, dependency, dependencyMap);
        } catch (CpeValidationException ex) {
            throw new UnexpectedAnalysisException(ex);
        }
    }

    private JSONObject fetchNpmAuditJson(File dependencyDirectory, boolean skipDevDependencies)
            throws AnalysisException {
        try {
            final List<String> args = new ArrayList<>();
            args.add(npmPath);
            args.add("audit");
            if (skipDevDependencies) {
                args.add("--omit=dev");
            }
            args.add("--json");
            final ProcessBuilder builder = new ProcessBuilder(args);
            builder.directory(dependencyDirectory);
            final File tmpFile = getSettings().getTempFile("npm_audit_yarn", "json");
            builder.redirectOutput(tmpFile);
            LOGGER.debug("Launching: {}", args);
            return getJsonObject(builder.start(), tmpFile);
        } catch (IOException ioe) {
            throw new AnalysisException("npm audit failure; this error can be ignored if you are not analyzing "
                    + "projects with a yarn lockfile.", ioe);
        }
    }

    private static @NonNull JSONObject getJsonObject(Process process, File tmpFile) throws IOException, AnalysisException {
        try (ProcessReader processReader = new ProcessReader(process)) {
            processReader.readAll();
            final String errOutput = processReader.getError();
            if (!StringUtils.isBlank(errOutput)) {
                LOGGER.debug("Process {} produced an error output: {}", process.info().command(), errOutput);
            }
            final String verboseJson = Files.readString(tmpFile.toPath());
            LOGGER.debug("Audit report: {}", verboseJson);
            return new JSONObject(verboseJson);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new AnalysisException("npm audit process was interrupted.", ex);
        } catch (JSONException e) {
            throw new AnalysisException("npm audit returned an invalid response.", e);
        } finally {
            Files.delete(tmpFile.toPath());
        }
    }

    private static File getDependencyDirectory(File lockFile) {
        final File folder = lockFile.getParentFile();
        if (!folder.isDirectory()) {
            throw new IllegalArgumentException(String.format("%s should have been a directory.", folder.getAbsolutePath()));
        }
        return folder;
    }

    private List<Advisory> analyzePackageWithYarnClassic(final File lockFile, Dependency dependency)
            throws AnalysisException {
        try {
            final boolean skipDevDependencies =
                getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_SKIPDEV, false);
            final JSONObject auditJson = fetchNpmAuditJson(getDependencyDirectory(lockFile), skipDevDependencies);
            if (auditJson.optInt("auditReportVersion", 1) >= 2) {
                return new NpmAuditV2Parser().parse(auditJson, getDependencyDirectory(lockFile));
            }
            return new NpmAuditParser().parse(auditJson);
        } catch (JSONException e) {
            throw new AnalysisException(String.format("Failed to parse npm audit output for %s "
                    + "(YarnAuditAnalyzer).", lockFile.getPath()), e);
        } catch (SearchException ex) {
            LOGGER.error("YarnAuditAnalyzer failed on {}", dependency.getActualFilePath());
            throw ex;
        }
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
        final ProcessBuilder builder = new ProcessBuilder(args);
        builder.directory(getDependencyDirectory(dependency.getActualFile()));

        final String advisoriesJsons = startAndReadStdoutToString(builder);

        LOGGER.debug("Advisories JSON: {}", advisoriesJsons);
        final String[] advisoriesJsonArray = Stream.of(advisoriesJsons.split("\n"))
                .filter(s -> !s.isBlank())
                .toArray(String[]::new);
        try {
            final List<JSONObject> advisories = new ArrayList<>();
            for (String advisoriesJson : advisoriesJsonArray) {
                advisories.add(new JSONObject(advisoriesJson));
            }

            return advisories;
        } catch (JSONException e) {
            throw new AnalysisException("Failed to parse the response from NPM Audit API "
                    + "(YarnBerryAuditAnalyzer).", e);
        }
    }

    /**
     * Analyzes the package and yarn lock files by calling yarn npm audit and returning the identified advisories.
     *
     * @param dependency a reference to the dependency-object for the yarn.lock
     * @return a list of advisories
     */
    private List<Advisory> analyzePackageWithYarnBerry(Dependency dependency) throws AnalysisException {
        try {
            final var skipDevDependencies = getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_SKIPDEV, false);
            final var advisoryJsons = fetchYarnAdvisories(dependency, skipDevDependencies);
            return parseAdvisoryJsons(advisoryJsons);
        } catch (JSONException e) {
            throw new AnalysisException("Failed to parse the response from NPM Audit API "
                    + "(YarnBerryAuditAnalyzer).", e);
        } catch (SearchException ex) {
            LOGGER.error("YarnBerryAuditAnalyzer failed on {}", dependency.getActualFilePath());
            throw ex;
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
            final var ghsaId = NpmAuditV2Parser.extractGhsaId(url);
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

}
