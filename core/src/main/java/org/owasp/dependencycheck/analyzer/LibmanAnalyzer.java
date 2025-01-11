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
 * Copyright (c) 2023 The OWASP Foundation. All Rights Reserved.
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
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzer which parses a libman.json file to gather module information.
 *
 * @author Arjen Korevaar
 */
@ThreadSafe
public class LibmanAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    private static final String DEPENDENCY_ECOSYSTEM = Ecosystem.NODEJS;

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(LibmanAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Libman Analyzer";

    /**
     * The phase in which the analyzer runs.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final String FILE_NAME = "libman.json";

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFilenames(FILE_NAME).build();

    /**
     * Regex used to match Library property.
     */
    private static final Pattern LIBRARY_REGEX = Pattern
            .compile("(\\@(?<package>[a-zA-Z]+)\\/)?(?<name>.+)\\@(?<version>.+)", Pattern.CASE_INSENSITIVE);

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException if there's an error during initialization
     */
    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        // nothing to initialize
    }

    /**
     * Returns the analyzer's name.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the key used in the properties file to reference the analyzer's
     * enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_LIBMAN_ENABLED;
    }

    /**
     * Returns the analysis phase under which the analyzer runs.
     *
     * @return the phase under which this analyzer runs
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * Performs the analysis.
     *
     * @param dependency the dependency to analyze
     * @param engine     the engine
     * @throws AnalysisException when there's an exception during analysis
     */
    @Override
    public void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        LOGGER.debug("Checking file {}", dependency.getActualFilePath());

        if (FILE_NAME.equals(dependency.getFileName()) && !dependency.isVirtual()) {
            engine.removeDependency(dependency);
        }

        final File dependencyFile = dependency.getActualFile();

        if (!dependencyFile.isFile() || dependencyFile.length() == 0) {
            return;
        }

        try (JsonReader jsonReader = Json.createReader(Files.newInputStream(dependencyFile.toPath()))) {
            final JsonObject json = jsonReader.readObject();

            final String libmanVersion = json.getString("version");

            if (!"1.0".equals(libmanVersion)) {
                LOGGER.warn("The Libman analyzer currently only supports Libman version 1.0");
                return;
            }

            final String defaultProvider = json.getString("defaultProvider");
            final JsonArray libraries = json.getJsonArray("libraries");

            libraries.forEach(e -> {
                final JsonObject reference = (JsonObject) e;

                final String provider = reference.getString("provider", defaultProvider);
                final String library = reference.getString("library");

                if ("filesystem".equals(provider)) {
                    LOGGER.warn("Unable to determine name and version for filesystem package: {}", library);
                    return;
                }

                final Matcher matcher = LIBRARY_REGEX.matcher(library);

                if (!matcher.find()) {
                    LOGGER.warn("Unable to parse library, unknown format: {}", library);
                    return;
                }

                final String vendor = matcher.group("package");
                final String name = matcher.group("name");
                final String version = matcher.group("version");

                LOGGER.debug("Found Libman package: vendor {}, name {}, version {}", vendor, name, version);

                final Dependency child = new Dependency(dependency.getActualFile(), true);

                child.setEcosystem(DEPENDENCY_ECOSYSTEM);
                child.setName(name);
                child.setVersion(version);

                if (vendor != null) {
                    child.addEvidence(EvidenceType.VENDOR, FILE_NAME, "vendor", vendor, Confidence.HIGHEST);    
                }
                child.addEvidence(EvidenceType.VENDOR, FILE_NAME, "name", name, Confidence.HIGH);
                child.addEvidence(EvidenceType.PRODUCT, FILE_NAME, "name", name, Confidence.HIGHEST);
                child.addEvidence(EvidenceType.VERSION, FILE_NAME, "version", version, Confidence.HIGHEST);

                final String packagePath = String.format("%s:%s", name, version);

                child.setSha1sum(Checksum.getSHA1Checksum(packagePath));
                child.setSha256sum(Checksum.getSHA256Checksum(packagePath));
                child.setMd5sum(Checksum.getMD5Checksum(packagePath));
                child.setPackagePath(packagePath);

                try {
                    final PackageURL purl = PackageURLBuilder.aPackageURL()
                            .withType("libman")
                            .withName(name)
                            .withVersion(version)
                            .build();
                    final PurlIdentifier id = new PurlIdentifier(purl, Confidence.HIGHEST);
                    child.addSoftwareIdentifier(id);
                } catch (MalformedPackageURLException ex) {
                    LOGGER.warn("Unable to build package url for {}", ex.toString());
                }

                engine.addDependency(child);
            });
        } catch (JsonException e) {
            LOGGER.warn(String.format("Failed to parse %s file", FILE_NAME), e);
        } catch (IOException e) {
            throw new AnalysisException("Problem occurred while reading dependency file", e);
        }
    }
}
