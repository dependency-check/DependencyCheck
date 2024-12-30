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
 * Copyright (c) 2018 Nicolas Henneaux. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.artifactory.ArtifactorySearch;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import org.owasp.dependencycheck.xml.pom.PomUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.File;
import java.io.FileFilter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.util.List;

/**
 * Analyzer which will attempt to locate a dependency, and the GAV information,
 * by querying Artifactory for the dependency's hashes digest.
 *
 * @author nhenneaux
 */
@ThreadSafe
public class ArtifactoryAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ArtifactoryAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Artifactory Analyzer";

    /**
     * The phase in which this analyzer runs.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The types of files on which this will work.
     */
    private static final String SUPPORTED_EXTENSIONS = "jar";

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(SUPPORTED_EXTENSIONS).build();

    /**
     * The searcher itself.
     */
    private ArtifactorySearch searcher;

    /**
     * Initializes the analyzer with the configured settings.
     *
     * @param settings the configured settings to use
     */
    @Override
    public synchronized void initialize(Settings settings) {
        super.initialize(settings);
        setEnabled(checkEnabled());
    }

    /**
     * Whether the analyzer is configured to support parallel processing.
     *
     * @return true if configured to support parallel processing; otherwise
     * false
     */
    @Override
    public boolean supportsParallelProcessing() {
        return getSettings().getBoolean(Settings.KEYS.ANALYZER_ARTIFACTORY_PARALLEL_ANALYSIS, true);
    }

    /**
     * Determines if this analyzer is enabled.
     *
     * @return <code>true</code> if the analyzer is enabled; otherwise
     * <code>false</code>
     */
    private boolean checkEnabled() {
        try {
            return getSettings().getBoolean(Settings.KEYS.ANALYZER_ARTIFACTORY_ENABLED);
        } catch (InvalidSettingException ise) {
            LOGGER.warn("Invalid setting. Disabling the Artifactory analyzer");
        }
        return false;
    }

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException thrown when the analyzer is unable to
     * connect to Artifactory
     */
    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        LOGGER.debug("Initializing Artifactory analyzer");
        final boolean enabled = isEnabled();
        LOGGER.debug("Artifactory analyzer enabled: {}", enabled);
        if (enabled) {
            searcher = new ArtifactorySearch(getSettings());
            final boolean preflightRequest = searcher.preflightRequest();
            if (!preflightRequest) {
                setEnabled(false);
                throw new InitializationException("There was an issue connecting to Artifactory . Disabling analyzer.");
            }
        }
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
     * Returns the key used in the properties file to to reference the
     * analyzer's enabled property.
     *
     * @return the analyzer's enabled property setting key.
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_ARTIFACTORY_ENABLED;
    }

    /**
     * Returns the analysis phase under which the analyzer runs.
     *
     * @return the phase under which the analyzer runs
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

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
        for (Evidence e : dependency.getEvidence(EvidenceType.VENDOR)) {
            if ("pom".equals(e.getSource())) {
                return;
            }
        }
        try {
            final List<MavenArtifact> mas = searcher.search(dependency);
            final Confidence confidence = mas.size() > 1 ? Confidence.HIGH : Confidence.HIGHEST;
            for (MavenArtifact ma : mas) {
                LOGGER.debug("Artifactory analyzer found artifact ({}) for dependency ({})", ma, dependency.getFileName());
                dependency.addAsEvidence("artifactory", ma, confidence);

                if (ma.getPomUrl() != null) {
                    processPom(dependency, ma);
                }
            }
        } catch (IllegalArgumentException iae) {
            LOGGER.info("invalid sha1-hash on {}", dependency.getFileName());
        } catch (FileNotFoundException fnfe) {
            LOGGER.debug("Artifact not found in repository: '{}", dependency.getFileName());
        } catch (IOException ioe) {
            final String message = "Could not connect to Artifactory search. Analysis failed.";
            LOGGER.error(message, ioe);
            throw new AnalysisException(message, ioe);
        }
    }

    /**
     * If necessary, downloads the pom.xml from Central and adds the evidence to
     * the dependency.
     *
     * @param dependency the dependency to download and process the pom.xml
     * @param ma the Maven artifact coordinates
     * @throws IOException thrown if there is an I/O error
     * @throws AnalysisException thrown if there is an error analyzing the pom
     */
    private void processPom(Dependency dependency, MavenArtifact ma) throws IOException, AnalysisException {
        File pomFile = null;
        try {
            final File baseDir = getSettings().getTempDirectory();
            pomFile = File.createTempFile("pom", ".xml", baseDir);
            Files.delete(pomFile.toPath());
            LOGGER.debug("Downloading {}", ma.getPomUrl());
            //TODO add caching
            Downloader.getInstance().fetchFile(new URL(ma.getPomUrl()), pomFile, true,
                    Settings.KEYS.ANALYZER_ARTIFACTORY_API_USERNAME,
                    Settings.KEYS.ANALYZER_ARTIFACTORY_API_TOKEN,
                    Settings.KEYS.ANALYZER_ARTIFACTORY_BEARER_TOKEN);
            PomUtils.analyzePOM(dependency, pomFile);

        } catch (DownloadFailedException ex) {
            LOGGER.warn("Unable to download pom.xml for {} from Artifactory; "
                    + "this could result in undetected CPE/CVEs.", dependency.getFileName());
        } catch (TooManyRequestsException ex) {
            this.setEnabled(false);
            throw new AnalysisException("Received a 429 - too many requests from Artifactory; "
                    + "the artifactory analyzer is being disabled.", ex);
        } catch (ResourceNotFoundException ex) {
            LOGGER.warn("pom.xml not found for {} from Artifactory; "
                    + "this could result in undetected CPE/CVEs.", dependency.getFileName());
        } finally {
            if (pomFile != null && pomFile.exists() && !FileUtils.delete(pomFile)) {
                LOGGER.debug("Failed to delete temporary pom file {}", pomFile);
                pomFile.deleteOnExit();
            }
        }
    }

}
