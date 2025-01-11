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
import org.owasp.dependencycheck.data.nuget.NugetPackage;
import org.owasp.dependencycheck.data.nuget.NuspecParseException;
import org.owasp.dependencycheck.data.nuget.XPathNuspecParser;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;

/**
 * Analyzer which will parse a Nuspec file to gather module information.
 *
 * @author colezlaw
 */
@ThreadSafe
public class NuspecAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.DOTNET;

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NuspecAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Nuspec Analyzer";

    /**
     * The phase in which the analyzer runs.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The types of files on which this will work.
     */
    private static final String SUPPORTED_EXTENSIONS = "nuspec";
    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(SUPPORTED_EXTENSIONS).build();

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
        return Settings.KEYS.ANALYZER_NUSPEC_ENABLED;
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
    public void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        LOGGER.debug("Checking Nuspec file {}", dependency);
        try {
            final XPathNuspecParser parser = new XPathNuspecParser();
            final NugetPackage np;
            try (FileInputStream fis = new FileInputStream(dependency.getActualFilePath())) {
                np = parser.parse(fis);
            } catch (NuspecParseException | FileNotFoundException ex) {
                throw new AnalysisException(ex);
            }

            dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
            if (np.getOwners() != null) {
                dependency.addEvidence(EvidenceType.VENDOR, "nuspec", "owners", np.getOwners(), Confidence.HIGHEST);
            }
            dependency.addEvidence(EvidenceType.VENDOR, "nuspec", "authors", np.getAuthors(), Confidence.HIGH);
            dependency.addEvidence(EvidenceType.VERSION, "nuspec", "version", np.getVersion(), Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.PRODUCT, "nuspec", "id", np.getId(), Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.VENDOR, "nuspec", "id", np.getId(), Confidence.HIGH);
            dependency.addEvidence(EvidenceType.VENDOR, "nuspec", "description", np.getDescription(), Confidence.LOW);
            dependency.addEvidence(EvidenceType.PRODUCT, "nuspec", "description", np.getDescription(), Confidence.LOW);
            dependency.setName(np.getId());
            dependency.setVersion(np.getVersion());
            try {
                final PackageURL purl = PackageURLBuilder.aPackageURL().withType("nuget").withName(np.getId()).withVersion(np.getVersion()).build();
                dependency.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
            } catch (MalformedPackageURLException ex) {
                LOGGER.debug("Unable to build package url for nuspec", ex);
                final GenericIdentifier gid = new GenericIdentifier("nuspec:" + np.getId() + "@" + np.getVersion(), Confidence.HIGHEST);
                dependency.addSoftwareIdentifier(gid);
            }
            final String packagePath = String.format("%s:%s", np.getId(), np.getVersion());
            dependency.setPackagePath(packagePath);
            dependency.setDisplayFileName(packagePath);
            if (np.getLicenseUrl() != null && !np.getLicenseUrl().isEmpty()) {
                dependency.setLicense(np.getLicenseUrl());
            }
            if (np.getTitle() != null) {
                dependency.addEvidence(EvidenceType.PRODUCT, "nuspec", "title", np.getTitle(), Confidence.MEDIUM);
                dependency.addEvidence(EvidenceType.VENDOR, "nuspec", "title", np.getTitle(), Confidence.LOW);
            }
        } catch (Throwable e) {
            throw new AnalysisException(e);
        }
    }
}
