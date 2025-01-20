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
 * Copyright (c) 2018 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.analyzer.exception.SearchException;
import org.owasp.dependencycheck.analyzer.exception.UnexpectedAnalysisException;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.data.nodeaudit.NpmPayloadBuilder;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFailureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.exceptions.CpeValidationException;

import javax.annotation.concurrent.ThreadSafe;
import jakarta.json.Json;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

/**
 * Used to analyze Node Package Manager (npm) package-lock.json and
 * npm-shrinkwrap.json files via NPM Audit API.
 *
 * @author Steve Springett
 */
@ThreadSafe
public class NodeAuditAnalyzer extends AbstractNpmAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NodeAuditAnalyzer.class);
    /**
     * The default URL to the NPM Audit API.
     */
    public static final String DEFAULT_URL = "https://registry.npmjs.org/-/npm/v1/security/audits";
    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.NODEJS;
    /**
     * The file name to scan.
     */
    public static final String PACKAGE_LOCK_JSON = "package-lock.json";
    /**
     * The file name to scan.
     */
    public static final String SHRINKWRAP_JSON = "npm-shrinkwrap.json";

    /**
     * Filter that detects files named "package-lock.json or
     * npm-shrinkwrap.json".
     */
    private static final FileFilter PACKAGE_JSON_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(PACKAGE_LOCK_JSON, SHRINKWRAP_JSON).build();

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return PACKAGE_JSON_FILTER;
    }

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    @Override
    public String getName() {
        return "Node Audit Analyzer";
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINDING_ANALYSIS;
    }

    /**
     * Returns the key used in the properties file to determine if the analyzer
     * is enabled.
     *
     * @return the enabled property setting key for the analyzer
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (dependency.getDisplayFileName().equals(dependency.getFileName())) {
            engine.removeDependency(dependency);
        }
        final File packageLock = dependency.getActualFile();
        final File shrinkwrap = new File(packageLock.getParentFile(), SHRINKWRAP_JSON);
        if (PACKAGE_LOCK_JSON.equals(dependency.getFileName()) && shrinkwrap.isFile()) {
            LOGGER.debug("Skipping {} because shrinkwrap lock file exists", dependency.getFilePath());
            return;
        }
        if (!packageLock.isFile() || packageLock.length() == 0 || !shouldProcess(packageLock)) {
            return;
        }
        final File packageJson = new File(packageLock.getParentFile(), "package.json");
        final List<Advisory> advisories;
        final MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        //final Map<String, String> dependencyMap = new HashMap<>();
        if (packageJson.isFile()) {
            advisories = analyzePackage(packageLock, packageJson, dependency, dependencyMap);
        } else {
            advisories = legacyAnalysis(packageLock, dependency, dependencyMap);
        }
        try {
            processResults(advisories, engine, dependency, dependencyMap);
        } catch (CpeValidationException ex) {
            throw new UnexpectedAnalysisException(ex);
        }
    }

    /**
     * Analyzes the package and package-lock files by extracting dependency
     * information, creating a payload to submit to the npm audit API,
     * submitting the payload, and returning the identified advisories.
     *
     * @param lockFile a reference to the package-lock.json
     * @param packageFile a reference to the package.json
     * @param dependency a reference to the dependency-object for the
     * package-lock.json
     * @param dependencyMap a collection of module/version pairs; during
     * creation of the payload the dependency map is populated with the
     * module/version information.
     * @return a list of advisories
     * @throws AnalysisException thrown when there is an error creating or
     * submitting the npm audit API payload
     */
    private List<Advisory> analyzePackage(final File lockFile, final File packageFile,
                                          Dependency dependency, MultiValuedMap<String, String> dependencyMap)
            throws AnalysisException {
        try {
            final JsonReader packageReader = Json.createReader(Files.newInputStream(packageFile.toPath()));
            final JsonReader lockReader = Json.createReader(Files.newInputStream(lockFile.toPath()));
            // Retrieves the contents of package-lock.json from the Dependency
            final JsonObject lockJson = lockReader.readObject();
            // Retrieves the contents of package-lock.json from the Dependency
            final JsonObject packageJson = packageReader.readObject();

            // Modify the payload to meet the NPM Audit API requirements
            final JsonObject payload = NpmPayloadBuilder.build(lockJson, packageJson, dependencyMap,
                    getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_SKIPDEV, false));

            // Submits the package payload to the nsp check service
            return getSearcher().submitPackage(payload);

        } catch (URLConnectionFailureException e) {
            this.setEnabled(false);
            throw new AnalysisException("Failed to connect to the NPM Audit API (NodeAuditAnalyzer); the analyzer "
                    + "is being disabled and may result in false negatives.", e);
        } catch (IOException e) {
            LOGGER.debug("Error reading dependency or connecting to NPM Audit API", e);
            this.setEnabled(false);
            throw new AnalysisException("Failed to read results from the NPM Audit API (NodeAuditAnalyzer); "
                    + "the analyzer is being disabled and may result in false negatives.", e);
        } catch (JsonException e) {
            throw new AnalysisException(String.format("Failed to parse %s file from the NPM Audit API "
                    + "(NodeAuditAnalyzer).", lockFile.getPath()), e);
        } catch (SearchException e) {
            final File yarnCheck = new File(lockFile.getParentFile(), "yarn.lock");
            if (yarnCheck.exists()) {
                final String msg = "NodeAuditAnalyzer failed on " + dependency.getActualFilePath()
                        + " - yarn.lock was found; if package-lock.json was generated using synp, it may not be in the correct format.";
                LOGGER.error(msg);
                throw new AnalysisException(msg, e);
            }
            LOGGER.error("NodeAuditAnalyzer failed on {}", dependency.getActualFilePath());
            throw e;
        }
    }

    /**
     * Analyzes the package and package-lock files by extracting dependency
     * information, creating a payload to submit to the npm audit API,
     * submitting the payload, and returning the identified advisories.
     *
     * @param file a reference to the package-lock.json
     * @param dependency a reference to the dependency-object for the
     * package-lock.json
     * @param dependencyMap a collection of module/version pairs; during
     * creation of the payload the dependency map is populated with the
     * module/version information.
     * @return a list of advisories
     * @throws AnalysisException thrown when there is an error creating or
     * submitting the npm audit API payload
     */
    private List<Advisory> legacyAnalysis(final File file, Dependency dependency, MultiValuedMap<String, String> dependencyMap)
            throws AnalysisException {

        try (JsonReader jsonReader = Json.createReader(Files.newInputStream(file.toPath()))) {

            // Retrieves the contents of package-lock.json from the Dependency
            final JsonObject packageJson = jsonReader.readObject();

            final String projectName = packageJson.getString("name", "");
            final String projectVersion = packageJson.getString("version", "");
            if (!projectName.isEmpty()) {
                dependency.setName(projectName);
            }
            if (!projectVersion.isEmpty()) {
                dependency.setVersion(projectVersion);
            }

            // Modify the payload to meet the NPM Audit API requirements
            final JsonObject payload = NpmPayloadBuilder.build(packageJson, dependencyMap,
                    getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_SKIPDEV, false));

            // Submits the package payload to the nsp check service
            return getSearcher().submitPackage(payload);

        } catch (URLConnectionFailureException e) {
            this.setEnabled(false);
            throw new AnalysisException("Failed to connect to the NPM Audit API (NodeAuditAnalyzer); the analyzer "
                    + "is being disabled and may result in false negatives.", e);
        } catch (IOException e) {
            LOGGER.debug("Error reading dependency or connecting to NPM Audit API", e);
            this.setEnabled(false);
            throw new AnalysisException("Failed to read results from the NPM Audit API (NodeAuditAnalyzer); "
                    + "the analyzer is being disabled and may result in false negatives.", e);
        } catch (JsonException e) {
            throw new AnalysisException(String.format("Failed to parse %s file from the NPM Audit API "
                    + "(NodeAuditAnalyzer).", file.getPath()), e);
        } catch (SearchException ex) {
            LOGGER.error("NodeAuditAnalyzer failed on {}", dependency.getActualFilePath());
            throw ex;
        }
    }
}
