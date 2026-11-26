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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
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
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.processing.ProcessReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.exceptions.CpeValidationException;

import javax.annotation.concurrent.ThreadSafe;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.owasp.dependencycheck.utils.FileUtils.existsWithContent;

@ThreadSafe
public class PnpmAuditAnalyzer extends AbstractNpmAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(PnpmAuditAnalyzer.class);

    /**
     * The file name to scan.
     */
    public static final String PNPM_PACKAGE_LOCK = "pnpm-lock.yaml";

    /**
     * The default registry parameter to pass to the pnpm audit execution.
     */
    public static final String DEFAULT_REGISTRY = "https://registry.npmjs.org/";

    /**
     * Filter that detects files named "pnpm-lock.yaml"
     */
    private static final FileFilter LOCK_FILE_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(PNPM_PACKAGE_LOCK).build();

    /**
     * The path to the `pnpm` executable.
     */
    private String pnpmPath;

    /**
     * Analyzes the pnpm lock file to determine vulnerable dependencies. Uses
     * pnpm audit --json to vulnerabilities report from NPM API.
     *
     * @param dependency the pnpm lock file
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
        final boolean skipDevDependencies = getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_SKIPDEV, false);
        final MultiValuedMap<String, String> dependencyMap = buildDependencyMap(packageLock, skipDevDependencies);
        final List<Advisory> advisories = analyzePackage(packageLock, dependency, skipDevDependencies);
        try {
            processResults(advisories, engine, dependency, dependencyMap);
        } catch (CpeValidationException ex) {
            throw new UnexpectedAnalysisException(ex);
        }
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_PNPM_AUDIT_ENABLED;
    }

    @Override
    protected FileFilter getFileFilter() {
        return LOCK_FILE_FILTER;
    }

    @Override
    public String getName() {
        return "Pnpm Audit Analyzer";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINDING_ANALYSIS;
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
            LOGGER.debug("{} Analyzer is disabled skipping pnpm executable check", getName());
            return;
        }
        final List<String> args = new ArrayList<>();
        args.add(getPnpm());
        args.add("--help");
        final ProcessBuilder builder = new ProcessBuilder(args);
        LOGGER.debug("Launching: {}", args);
        try {
            final Process process = builder.start();
            try (ProcessReader processReader = new ProcessReader(process)) {
                processReader.readAll();
                final int exitValue = process.waitFor();
                final int expectedExitValue = 0;
                final int executableNotFoundExitValue = 127;
                switch (exitValue) {
                    case expectedExitValue:
                        LOGGER.debug("{} is enabled.", getName());
                        break;
                    case executableNotFoundExitValue:
                    default:
                        this.setEnabled(false);
                        LOGGER.warn("The {} has been disabled. Pnpm executable was not found.", getName());
                }
            }
        } catch (Exception ex) {
            this.setEnabled(false);
            LOGGER.warn("The {} has been disabled. Pnpm executable was not found.", getName());
            throw new InitializationException("Unable to read pnpm audit output.", ex);
        }
    }

    /**
     * Attempts to determine the path to `pnpm`.
     *
     * @return the path to `pnpm`
     */
    private String getPnpm() {
        final String value;
        synchronized (this) {
            if (pnpmPath == null) {
                final String path = getSettings().getString(Settings.KEYS.ANALYZER_PNPM_PATH);
                if (path == null) {
                    pnpmPath = "pnpm";
                } else {
                    final File pnpmFile = new File(path);
                    if (pnpmFile.isFile()) {
                        pnpmPath = pnpmFile.getAbsolutePath();
                    } else {
                        LOGGER.warn("Provided path to `pnpm` executable is invalid.");
                        pnpmPath = "pnpm";
                    }
                }
            }
            value = pnpmPath;
        }
        return value;
    }

    private JSONObject fetchPnpmAuditJson(Dependency dependency, boolean skipDevDependencies) throws AnalysisException {
        final File folder = dependency.getActualFile().getParentFile();
        if (!folder.isDirectory()) {
            throw new AnalysisException(String.format("%s should have been a directory.", folder.getAbsolutePath()));
        }
        try {
            final List<String> args = new ArrayList<>();

            args.add(getPnpm());
            args.add("audit");
            if (skipDevDependencies) {
                args.add("--prod");
            }
            // pnpm audit returns a json compliant with NpmAuditParser
            args.add("--json");
            // ensure we are using the right registry despite .npmrc, but allow override
            args.add("--registry");
            args.add(getSettings().getString(Settings.KEYS.ANALYZER_PNPM_AUDIT_REGISTRY, DEFAULT_REGISTRY));
            final ProcessBuilder builder = new ProcessBuilder(args);
            builder.directory(folder);
            // Workaround 64k limitation of InputStream, redirect stdout to a file that we will read later
            // instead of reading directly stdout from Process's InputStream which is topped at 64k
            final File tmpFile = File.createTempFile("pnpm_audit", null);
            builder.redirectOutput(tmpFile);
            LOGGER.debug("Launching: {}", args);
            final Process process = builder.start();
            try (ProcessReader processReader = new ProcessReader(process)) {
                processReader.readAll();
                final String errOutput = processReader.getError();
                if (!StringUtils.isBlank(errOutput)) {
                    LOGGER.error("Process error output: {}", errOutput);
                }
                String verboseJson = new String(Files.readAllBytes(tmpFile.toPath()), StandardCharsets.UTF_8);
                // Workaround implicit creation of .pnpm-debug.log, see https://github.com/pnpm/pnpm/issues/3832
                // affects usage of docker container to analyze mounted directories without privileges
                if (verboseJson.contains("EACCES: permission denied, open 'node_modules/.pnpm-debug.log'")) {
                    verboseJson = verboseJson.substring(0, verboseJson.indexOf("EACCES: permission denied, open 'node_modules/.pnpm-debug.log'"));
                }
                LOGGER.debug("Audit report: {}", verboseJson);
                return new JSONObject(verboseJson);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new AnalysisException("Pnpm audit process was interrupted.", ex);
            } catch (JSONException e) {
                Thread.currentThread().interrupt();
                throw new AnalysisException("Pnpm audit returned an invalid response.", e);
            } finally {
                if (!tmpFile.delete()) {
                    LOGGER.debug("Unable to delete temp file: {}", tmpFile);
                }
            }
        } catch (IOException ioe) {
            throw new AnalysisException("pnpm audit failure; this error can be ignored if you are not analyzing projects with a pnpm lockfile.", ioe);
        }
    }

    /**
     * Analyzes the package and pnpm lock files by extracting dependency
     * information, creating a payload to submit to the npm audit API,
     * submitting the payload, and returning the identified advisories.
     *
     * @param lockFile a reference to the pnpm-lock.yaml
     * @param dependency a reference to the dependency-object for the
     * pnpm-lock.yaml
     * @param skipDevDependencies whether dev dependencies should be skipped
     * @return a list of advisories
     * @throws AnalysisException thrown when there is an error creating or
     * submitting the npm audit API payload
     */
    private List<Advisory> analyzePackage(final File lockFile,
            Dependency dependency, boolean skipDevDependencies)
            throws AnalysisException {
        try {
            // Use pnpm directly to fetch audit.json
            final JSONObject auditJson = fetchPnpmAuditJson(dependency, skipDevDependencies);
            // Submits the package payload to the nsp check service
            return getAuditParser().parse(auditJson);

        } catch (JSONException e) {
            throw new AnalysisException(String.format("Failed to parse %s file from the NPM Audit API "
                    + "(PnpmAuditAnalyzer).", lockFile.getPath()), e);
        } catch (SearchException ex) {
            LOGGER.error("PnpmAuditAnalyzer failed on {}", dependency.getActualFilePath());
            throw ex;
        }
    }

    /**
     * Builds a map of module names to installed versions from {@code pnpm-lock.yaml}
     * (supporting v5, v6, and v9+ lockfile formats) as a fallback when an advisory
     * omits an explicit finding version.
     *
     * @param lockFile the {@code pnpm-lock.yaml} file
     * @param skipDevDependencies whether entries marked {@code dev: true} should be skipped
     * @return map of package names to resolved versions
     */
    MultiValuedMap<String, String> buildDependencyMap(final File lockFile, final boolean skipDevDependencies) {
        final MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        final ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        try {
            final JsonNode root = mapper.readTree(lockFile);
            if (root == null) {
                return dependencyMap;
            }
            final JsonNode packages = root.get("packages");
            if (packages == null || !packages.isObject()) {
                return dependencyMap;
            }
            final Iterator<Map.Entry<String, JsonNode>> fields = packages.fields();
            while (fields.hasNext()) {
                final Map.Entry<String, JsonNode> entry = fields.next();
                final JsonNode packageInfo = entry.getValue();
                if (skipDevDependencies && packageInfo != null && packageInfo.path("dev").asBoolean(false)) {
                    continue;
                }
                addLockPackageEntry(entry.getKey(), dependencyMap);
            }
        } catch (IOException ex) {
            LOGGER.debug("Unable to parse {} for dependency version fallback", lockFile, ex);
        }
        return dependencyMap;
    }

    /**
     * Parses a {@code pnpm-lock.yaml} {@code packages} key across v5
     * ({@code /pkg/1.0.0}, {@code /@scope/pkg/1.0.0}), v6 ({@code /pkg@1.0.0}),
     * and v9 ({@code pkg@1.0.0}) formats and adds it to {@code dependencyMap}.
     *
     * @param packageKey the YAML key under {@code packages}
     * @param dependencyMap the target map of package names to versions
     */
    private void addLockPackageEntry(final String packageKey, final MultiValuedMap<String, String> dependencyMap) {
        if (packageKey == null || packageKey.isEmpty()) {
            return;
        }
        String normalized = packageKey.startsWith("/") ? packageKey.substring(1) : packageKey;
        final int parenIdx = normalized.indexOf('(');
        if (parenIdx > 0) {
            normalized = normalized.substring(0, parenIdx);
        }
        final int splitIdx = findNameVersionSeparator(normalized);
        if (splitIdx <= 0 || splitIdx >= normalized.length() - 1) {
            return;
        }
        final String name = normalized.substring(0, splitIdx);
        String version = normalized.substring(splitIdx + 1);
        final int underscoreIdx = version.indexOf('_');
        if (underscoreIdx > 0) {
            version = version.substring(0, underscoreIdx);
        }
        if (!name.isEmpty() && !name.contains(":")
                && !version.isEmpty() && !version.contains(":") && !version.contains("/")) {
            dependencyMap.put(name, version);
        }
    }

    /**
     * Finds the index separating the npm package name and version in a normalized
     * pnpm lockfile package key.
     *
     * @param normalized the normalized lockfile key without leading slash or peer parens
     * @return the separator index, or {@code -1} if invalid
     */
    private int findNameVersionSeparator(final String normalized) {
        final int searchStart;
        if (normalized.startsWith("@")) {
            final int scopeSlash = normalized.indexOf('/');
            if (scopeSlash <= 1) {
                return -1;
            }
            searchStart = scopeSlash + 1;
        } else {
            searchStart = 1;
        }
        final int atIdx = normalized.indexOf('@', searchStart);
        final int slashIdx = normalized.indexOf('/', searchStart);
        if (slashIdx > searchStart && (atIdx < 0 || slashIdx < atIdx)) {
            return slashIdx;
        }
        if (atIdx > searchStart) {
            return atIdx;
        }
        return -1;
    }

    @NonNull
    private NpmAuditParser getAuditParser() {
        return new NpmAuditParser();
    }
}
