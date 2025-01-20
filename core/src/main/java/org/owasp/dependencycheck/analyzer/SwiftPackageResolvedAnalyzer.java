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
 * Copyright (c) 2021 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import java.io.FileFilter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

/**
 * This analyzer is used to analyze the SWIFT Package Resolved
 * (https://swift.org/package-manager/). It collects information about a package
 * from Package.resolved files.
 *
 * @author Jorge Mendes (https://twitter.com/Jorzze)
 */
@Experimental
@ThreadSafe
public class SwiftPackageResolvedAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SwiftPackageResolvedAnalyzer.class);

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.IOS;

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "SWIFT Package Resolved Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The file name to scan.
     */
    public static final String SPM_RESOLVED_FILE_NAME = "Package.resolved";

    /**
     * Filter that detects files named "Package.resolved".
     */
    private static final FileFilter SPM_FILE_FILTER = FileFilterBuilder.newInstance().addFilenames(SPM_RESOLVED_FILE_NAME).build();

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return SPM_FILE_FILTER;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) {
        // NO-OP
    }

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * Returns the key used in the properties file to reference the analyzer's
     * enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_SWIFT_PACKAGE_RESOLVED_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        try {
            engine.removeDependency(dependency);
            analyzeSpmResolvedDependencies(dependency, engine);
        } catch (IOException ex) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file: " + dependency.getActualFilePath(), ex);
        }
    }

    /**
     * Analyzes the Package.resolved file to extract evidence for the
     * dependency.
     *
     * @param spmResolved the dependency to analyze
     * @param engine the analysis engine
     * @throws AnalysisException thrown if there is an error analyzing the
     * dependency
     */
    private void analyzeSpmResolvedDependencies(Dependency spmResolved, Engine engine)
            throws AnalysisException, IOException {

        try (InputStream in = Files.newInputStream(spmResolved.getActualFile().toPath());
             JsonReader resolved = Json.createReader(in)) {
            final JsonObject file = resolved.readObject();
            final int fileVersion = file.getInt("version");

            switch (fileVersion) {
                case 1:
                    analyzeSpmResolvedDependenciesV1(spmResolved, engine, file);
                    break;
                case 2:
                case 3:
                    analyzeSpmResolvedDependenciesV2And3(spmResolved, engine, file);
                    break;
                default:
                    return;
            }
        }
    }

    /**
     * Analyzes the version 1 of the Package.resolved file to extract evidence
     * for the dependency.
     *
     * @param spmResolved the dependency to analyze
     * @param engine the analysis engine
     * @param resolved the json object of the file to analyze
     */
    private void analyzeSpmResolvedDependenciesV1(Dependency spmResolved, Engine engine, JsonObject resolved) {
        final JsonObject object = resolved.getJsonObject("object");
        if (object == null) {
            return;
        }
        final JsonArray pins = object.getJsonArray("pins");
        if (pins == null) {
            return;
        }
        pins.forEach(row -> {
            final JsonObject pin = (JsonObject) row;
            final String name = pin.getString("package");
            final String repo = pin.getString("repositoryURL");
            String version = null;
            final JsonObject state = pin.getJsonObject("state");
            if (state != null) {
                if (!state.isNull("version")) {
                    version = state.getString("version");
                } else if (!state.isNull("branch")) {
                    version = state.getString("branch");
                }
            }
            final Dependency dependency = createDependency(spmResolved, SPM_RESOLVED_FILE_NAME, name, version, repo);
            engine.addDependency(dependency);
        });
    }

    /**
     * Analyzes the versions 2 and 3 of the Package.resolved file to extract evidence
     * for the dependency.
     *
     * @param spmResolved the dependency to analyze
     * @param engine the analysis engine
     * @param resolved the json object of the file to analyze
     */
    private void analyzeSpmResolvedDependenciesV2And3(Dependency spmResolved, Engine engine, JsonObject resolved) {
        final JsonArray pins = resolved.getJsonArray("pins");
        if (pins == null) {
            return;
        }
        pins.forEach(row -> {
            final JsonObject pin = (JsonObject) row;
            final String name = pin.getString("identity");
            final String repo = pin.getString("location");
            String version = null;
            final JsonObject state = pin.getJsonObject("state");
            if (state != null) {
                if (state.containsKey("version")
                        && !state.isNull("version")
                        && !state.getString("version").isEmpty()) {
                    version = state.getString("version");
                } else if (state.containsKey("branch") && !state.isNull("branch")) {
                    version = state.getString("branch");
                }
            }
            final Dependency dependency = createDependency(spmResolved, SPM_RESOLVED_FILE_NAME, name, version, repo);
            engine.addDependency(dependency);
        });
    }

    /**
     * Creates a dependency object.
     *
     * @param parent the parent dependency
     * @param source the source type
     * @param name the name of the dependency
     * @param version the version of the dependency
     * @param repo the repository URL of the dependency
     * @return the newly created dependency object
     */
    private Dependency createDependency(Dependency parent, String source, final String name, String version, String repo) {
        final Dependency dependency = new Dependency(parent.getActualFile(), true);
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
        dependency.setName(name);
        dependency.setVersion(version);
        final String packagePath = String.format("%s:%s", name, version);
        dependency.setPackagePath(packagePath);
        dependency.setDisplayFileName(packagePath);
        dependency.setSha1sum(Checksum.getSHA1Checksum(packagePath));
        dependency.setSha256sum(Checksum.getSHA256Checksum(packagePath));
        dependency.setMd5sum(Checksum.getMD5Checksum(packagePath));
        dependency.addEvidence(EvidenceType.VENDOR, source, "name", name, Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.PRODUCT, source, "name", name, Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VENDOR, source, "repositoryUrl", repo, Confidence.HIGH);
        dependency.addEvidence(EvidenceType.PRODUCT, source, "repositoryUrl", repo, Confidence.HIGH);
        dependency.addEvidence(EvidenceType.VERSION, source, "version", version, Confidence.HIGHEST);
        try {
            final PackageURLBuilder builder = PackageURLBuilder.aPackageURL().withType("swift").withName(dependency.getName());
            if (dependency.getVersion() != null) {
                builder.withVersion(dependency.getVersion());
            }
            final PackageURL purl = builder.build();
            dependency.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
        } catch (MalformedPackageURLException ex) {
            LOGGER.debug("Unable to build package url for swift dependency", ex);
            final GenericIdentifier id;
            if (dependency.getVersion() != null) {
                id = new GenericIdentifier("swift:" + dependency.getName() + "@" + dependency.getVersion(), Confidence.HIGHEST);
            } else {
                id = new GenericIdentifier("swift:" + dependency.getName(), Confidence.HIGHEST);
            }
            dependency.addSoftwareIdentifier(id);
        }
        return dependency;
    }
}
