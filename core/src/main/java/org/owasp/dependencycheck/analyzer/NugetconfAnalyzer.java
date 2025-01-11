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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nuget.NugetPackageReference;
import org.owasp.dependencycheck.data.nuget.NugetconfParseException;
import org.owasp.dependencycheck.data.nuget.XPathNugetconfParser;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.List;

import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;

/**
 * Analyzer which parses a Nuget packages.config file to gather module
 * information.
 *
 * @author doshyt
 */
@ThreadSafe
public class NugetconfAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.DOTNET;

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NugetconfAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Nugetconf Analyzer";

    /**
     * The phase in which the analyzer runs.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    public static final String FILE_NAME = "packages.config";

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFilenames(FILE_NAME).build();

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException if there's an error during initialization
     */
    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        //nothing to initialize
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
        return Settings.KEYS.ANALYZER_NUGETCONF_ENABLED;
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
     * @param engine the engine
     * @throws AnalysisException when there's an exception during analysis
     */
    @Override
    @SuppressWarnings("StringSplitter")
    public void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        LOGGER.debug("Checking packages.config file {}", dependency);
        try {
            final XPathNugetconfParser parser = new XPathNugetconfParser();
            final List<NugetPackageReference> packages;
            try (FileInputStream fis = new FileInputStream(dependency.getActualFilePath())) {
                packages = parser.parse(fis);
            } catch (NugetconfParseException | FileNotFoundException ex) {
                throw new AnalysisException(ex);
            }

            for (NugetPackageReference np : packages) {
                final Dependency child = new Dependency(dependency.getActualFile(), true);

                final String id = np.getId();
                final String version = np.getVersion();

                child.setEcosystem(DEPENDENCY_ECOSYSTEM);
                child.setName(id);
                child.setVersion(version);

                try {
                    final PackageURL purl = PackageURLBuilder.aPackageURL().withType("nuget").withName(id).withVersion(version).build();
                    child.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
                } catch (MalformedPackageURLException ex) {
                    LOGGER.debug("Unable to build package url for nuget package", ex);
                    final GenericIdentifier gid = new GenericIdentifier("nuget:" + id + "@" + version, Confidence.HIGHEST);
                    child.addSoftwareIdentifier(gid);
                }

                child.setPackagePath(String.format("%s:%s", id, version));
                child.setSha1sum(Checksum.getSHA1Checksum(String.format("%s:%s", id, version)));
                child.setSha256sum(Checksum.getSHA256Checksum(String.format("%s:%s", id, version)));
                child.setMd5sum(Checksum.getMD5Checksum(String.format("%s:%s", id, version)));
                child.addEvidence(EvidenceType.VERSION, "packages.config", "version", np.getVersion(), Confidence.HIGHEST);
                child.addEvidence(EvidenceType.PRODUCT, "packages.config", "id", np.getId(), Confidence.HIGHEST);
                child.addEvidence(EvidenceType.VENDOR, "packages.config", "id", np.getId(), Confidence.MEDIUM);

                // handle package names the same way as the MSBuild analyzer
                if (id.indexOf('.') > 0) {
                    final String[] parts = id.split("\\.");

                    // example: Microsoft.EntityFrameworkCore
                    child.addEvidence(EvidenceType.VENDOR, "packages.config", "id", parts[0], Confidence.MEDIUM);
                    child.addEvidence(EvidenceType.PRODUCT, "packages.config", "id", parts[1], Confidence.MEDIUM);
                    child.addEvidence(EvidenceType.VENDOR, "packages.config", "id", parts[1], Confidence.LOW);

                    if (parts.length > 2) {
                        final String rest = id.substring(id.indexOf('.') + 1);
                        child.addEvidence(EvidenceType.PRODUCT, "packages.config", "id", rest, Confidence.MEDIUM);
                        child.addEvidence(EvidenceType.VENDOR, "packages.config", "id", rest, Confidence.LOW);
                    }
                } else {
                    // example: jQuery
                    child.addEvidence(EvidenceType.VENDOR, "packages.config", "id", id, Confidence.LOW);
                }

                engine.addDependency(child);
            }
        } catch (Throwable e) {
            throw new AnalysisException(e);
        }
    }
}
