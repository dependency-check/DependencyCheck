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
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import jakarta.json.Json;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Set;

/**
 * Used to analyze dependencies defined in Pipfile.lock. This analyzer works in
 * tandem with the `PipfileAnalyzer` - and both analyzers use the same key to
 * enable/disable the analyzers. The PipfileAnalyzer will be skipped if the lock
 * file exists, as the lock will provide more accurate version numbers.
 *
 * @author jeremy.long
 */
@Experimental
@ThreadSafe
public class PipfilelockAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(PipfilelockAnalyzer.class);
    /**
     * "Pipfile.lock" file.
     */
    private static final String LOCKFILE = "Pipfile.lock";

    /**
     * The identifiedPackage of the analyzer.
     */
    private static final String ANALYZER_NAME = "Pipfile.lock Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFilenames(LOCKFILE).build();

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
     * Returns the identifiedPackage of the analyzer.
     *
     * @return the identifiedPackage of the analyzer.
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
        return Settings.KEYS.ANALYZER_PIPFILE_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        LOGGER.debug("Checking file {}", dependency.getActualFilePath());

        engine.removeDependency(dependency);

        final File dependencyFile = dependency.getActualFile();
        if (!dependencyFile.isFile() || dependencyFile.length() == 0) {
            return;
        }

        final File actualFile = dependency.getActualFile();
        try (FileInputStream fin = new FileInputStream(actualFile);
                InputStream in = new BufferedInputStream(fin);
                JsonReader jsonReader = Json.createReader(in)) {

            final JsonObject jsonLock = jsonReader.readObject();
            final JsonObject develop = jsonLock.getJsonObject("develop");
            final Set<String> keys = develop.keySet();
            for (String identifiedPackage : keys) {
                final JsonObject dep = develop.getJsonObject(identifiedPackage);
                final String selectedVersion = dep.getString("version", "").trim();
                if (selectedVersion.startsWith("==") && selectedVersion.length() > 2) {
                    final String identifiedVersion = selectedVersion.substring(2).trim();
                    LOGGER.debug("package, version: {} {}", identifiedPackage, identifiedVersion);

                    final Dependency d = new Dependency(dependency.getActualFile(), true);
                    d.setName(identifiedPackage);
                    d.setVersion(identifiedVersion);
                    try {
                        final PackageURL purl = PackageURLBuilder.aPackageURL()
                                .withType("pypi")
                                .withName(identifiedPackage)
                                .withVersion(identifiedVersion)
                                .build();
                        d.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
                    } catch (MalformedPackageURLException ex) {
                        LOGGER.debug("Unable to build package url for pypi", ex);
                        d.addSoftwareIdentifier(new GenericIdentifier("pypi:" + identifiedPackage + "@" + identifiedVersion, Confidence.HIGH));
                    }
                    d.setPackagePath(String.format("%s:%s", identifiedPackage, identifiedVersion));
                    d.setEcosystem(PythonDistributionAnalyzer.DEPENDENCY_ECOSYSTEM);
                    final String filePath = String.format("%s:%s/%s", dependency.getFilePath(), identifiedPackage, identifiedVersion);
                    d.setFilePath(filePath);
                    d.setSha1sum(Checksum.getSHA1Checksum(filePath));
                    d.setSha256sum(Checksum.getSHA256Checksum(filePath));
                    d.setMd5sum(Checksum.getMD5Checksum(filePath));
                    d.addEvidence(EvidenceType.VENDOR, LOCKFILE, "vendor", identifiedPackage, Confidence.HIGHEST);
                    d.addEvidence(EvidenceType.PRODUCT, LOCKFILE, "product", identifiedPackage, Confidence.HIGHEST);
                    d.addEvidence(EvidenceType.VERSION, LOCKFILE, "version", identifiedVersion, Confidence.HIGHEST);
                    engine.addDependency(d);
                } else {
                    LOGGER.debug("Skipping `{}`: Unknown version `{}` in `{}`", identifiedPackage, selectedVersion, dependency.getActualFilePath());
                }
            }
        } catch (FileNotFoundException ex) {
            throw new RuntimeException(ex);
        } catch (IOException | JsonException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Retrieves the contents of a given file.
     *
     * @param actualFile the file to read
     * @return the contents of the file
     * @throws AnalysisException thrown if there is an IO Exception
     */
    private String getFileContents(final File actualFile) throws AnalysisException {
        try {
            return new String(Files.readAllBytes(actualFile.toPath()), StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            throw new AnalysisException("Problem occurred while reading dependency file.", e);
        }
    }

    /**
     * Initializes the file type analyzer.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException thrown if there is an exception during
     * initialization
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        // No initialization needed.
    }
}
