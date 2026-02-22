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
import java.util.List;

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
        if (!packageLock.isFile() || packageLock.length() == 0 || !shouldProcess(packageLock)) {
            return;
        }
        final List<Advisory> advisories;
        final MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        advisories = analyzePackage(packageLock, dependency);
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
     * @return a list of advisories
     * @throws AnalysisException thrown when there is an error creating or
     * submitting the npm audit API payload
     */
    private List<Advisory> analyzePackage(final File lockFile,
            Dependency dependency)
            throws AnalysisException {
        try {
            final boolean skipDevDependencies = getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_SKIPDEV, false);

            // Use pnpm directly to fetch audit.json
            // Retrieves the contents of package-lock.json from the Dependency
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

    @NonNull
    private NpmAuditParser getAuditParser() {
        return new NpmAuditParser();
    }
}
