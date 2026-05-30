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


import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.data.nexus.NexusSearch;
import org.owasp.dependencycheck.data.nexus.NexusV2Search;
import org.owasp.dependencycheck.data.nexus.NexusV3Search;
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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Locale;

/**
 * Analyzer which will attempt to locate a dependency on a Nexus service by
 * SHA-1 digest of the dependency.
 *
 * There are two settings which govern this behavior:
 *
 * <ul>
 * <li>{@link org.owasp.dependencycheck.utils.Settings.KEYS#ANALYZER_NEXUS_ENABLED}
 * determines whether this analyzer is even enabled. This can be overridden by
 * setting the system property.</li>
 * <li>{@link org.owasp.dependencycheck.utils.Settings.KEYS#ANALYZER_NEXUS_URL}
 * the URL to a Nexus service to search by SHA-1. There is an expected
 * <code>%s</code> in this where the SHA-1 will get entered.</li>
 * </ul>
 *
 * @author colezlaw
 */
@ThreadSafe
public class NexusAnalyzer extends AbstractFileTypeAnalyzer {
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NexusAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Nexus Analyzer";

    /**
     * The phase in which the analyzer runs.
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
     * The Nexus Search to be set up for this analyzer.
     */
    private NexusSearch searcher;

    /**
     * Field indicating if the analyzer is enabled.
     */
    private boolean enabled = true;

    /**
     * Initializes the analyzer with the configured settings.
     *
     * @param settings the configured settings to use
     */
    @Override
    public void initialize(Settings settings) {
        super.initialize(settings);
        enabled = checkEnabled();
    }

    /**
     * Determines if this analyzer is enabled
     *
     * @return <code>true</code> if the analyzer is enabled; otherwise
     * <code>false</code>
     */
    private boolean checkEnabled() {
        /* Enable this analyzer ONLY if the Nexus URL has been set to something
         other than the default one (if it's the default one, we'll use the
         central analyzer) and it's enabled by the user.
         */
        boolean retval = false;
        try {
            if (getSettings().getBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED)) {
                if (getSettings().getString(Settings.KEYS.ANALYZER_NEXUS_URL) != null) {
                    retval = true;
                } else {
                    LOGGER.warn("Disabling Nexus analyzer - please specify the URL to a Nexus Server");
                }
            }
        } catch (InvalidSettingException ise) {
            LOGGER.warn("Invalid setting. Disabling Nexus analyzer");
        }

        return retval;
    }

    /**
     * Determine whether to enable this analyzer or not.
     *
     * @return whether the analyzer should be enabled
     */
    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException if there's an error during initialization
     */
    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        LOGGER.debug("Initializing Nexus Analyzer");
        LOGGER.debug("Nexus Analyzer enabled: {}", isEnabled());
        if (isEnabled()) {
            final boolean useProxy = useProxy();
            LOGGER.debug("Using proxy: {}", useProxy);
            searcher = createNexusSearchOrDisable(useProxy);
        }
    }

    /**
     * Creates a NexusSearch for the appropriate Nexus version (Nexus V2 and V3 supported).
     * <p>
     * If errors are encountered creating or validating the NexusSearch it disables this analyzer.
     *
     * @param useProxy Whether a proxy is to be used
     * @return A NexusSearch appropriate for the configured ANALYZER_NEXUS_URL
     * @throws InitializationException Upon errors creating of validating the ANALYZER_NEXUS_URL
     */
    @SuppressWarnings("removal")
    private NexusSearch createNexusSearchOrDisable(boolean useProxy) throws InitializationException {
        final Settings settings = getSettings();
        final String nexusRootURL = settings.getString(Settings.KEYS.ANALYZER_NEXUS_URL);
        final NexusSearch result;
        try {
            if (nexusRootURL.toLowerCase(Locale.ROOT).contains("service/local/")) {
                LOGGER.warn("Nexus v2 went EOL on 30 June 2025. Nexus v2 support within OWASP Dependency Check is deprecated " +
                        "and may be removed in the next major release. Continual support requires migration to Nexus v3");
                result = new NexusV2Search(settings, useProxy);
            } else {
                result = new NexusV3Search(settings, useProxy);
            }
            if (!result.preflightRequest()) {
                setEnabled(false);
                throw new InitializationException("There was an error getting Nexus status. Disabling NexusAnalyzer.");
            }
        } catch (MalformedURLException mue) {
            setEnabled(false);
            throw new InitializationException("Malformed URL to Nexus. Disabling NexusAnalyzer", mue);
        }
        return result;
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
        return Settings.KEYS.ANALYZER_NEXUS_ENABLED;
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
        if (!isEnabled()) {
            return;
        }
        try {
            final MavenArtifact ma = searcher.searchSha1(dependency.getSha1sum());
            dependency.addAsEvidence("nexus", ma, Confidence.HIGH);
            boolean pomAnalyzed = false;
            LOGGER.debug("POM URL {}", ma.getPomUrl());
            for (Evidence e : dependency.getEvidence(EvidenceType.VENDOR)) {
                if ("pom".equals(e.getSource())) {
                    pomAnalyzed = true;
                    break;
                }
            }
            if (!pomAnalyzed && ma.getPomUrl() != null) {
                File pomFile = null;
                try {
                    final File baseDir = getSettings().getTempDirectory();
                    pomFile = File.createTempFile("pom", ".xml", baseDir);
                    if (!pomFile.delete()) {
                        LOGGER.warn("Unable to fetch pom.xml for {} from Nexus repository; "
                                + "this could result in undetected CPE/CVEs.", dependency.getFileName());
                        LOGGER.debug("Unable to delete temp file");
                    }
                    LOGGER.debug("Downloading {}", ma.getPomUrl());
                    Downloader.getInstance().fetchFile(new URL(ma.getPomUrl()), pomFile);
                    PomUtils.analyzePOM(dependency, pomFile);
                } catch (DownloadFailedException ex) {
                    LOGGER.warn("Unable to download pom.xml for {} from Nexus repository; "
                            + "this could result in undetected CPE/CVEs.", dependency.getFileName());
                } catch (TooManyRequestsException ex) {
                    this.setEnabled(false);
                    throw new AnalysisException("Received a 429 - too many requests from nexus; "
                            + "the nexus analyzer is being disabled.", ex);
                } catch (ResourceNotFoundException ex) {
                    LOGGER.warn("pom.xml not found for {} from nexus; "
                            + "this could result in undetected CPE/CVEs.", dependency.getFileName());
                } finally {
                    if (pomFile != null && pomFile.exists() && !FileUtils.delete(pomFile)) {
                        LOGGER.debug("Failed to delete temporary pom file {}", pomFile);
                        pomFile.deleteOnExit();
                    }
                }
            }
        } catch (IllegalArgumentException iae) {
            //dependency.addAnalysisException(new AnalysisException("Invalid SHA-1"));
            LOGGER.info("invalid sha-1 hash on {}", dependency.getFileName());
        } catch (FileNotFoundException fnfe) {
            //dependency.addAnalysisException(new AnalysisException("Artifact not found on repository"));
            LOGGER.debug("Artifact not found in repository '{}'", dependency.getFileName());
            LOGGER.debug(fnfe.getMessage(), fnfe);
        } catch (IOException ioe) {
            //dependency.addAnalysisException(new AnalysisException("Could not connect to repository", ioe));
            LOGGER.debug("Could not connect to nexus repository", ioe);
        }
    }

    /**
     * Determine if a proxy should be used for the Nexus Analyzer.
     *
     * @return {@code true} if a proxy should be used
     */
    public boolean useProxy() {
        try {
            return getSettings().getBoolean(Settings.KEYS.ANALYZER_NEXUS_USES_PROXY);
        } catch (InvalidSettingException ise) {
            LOGGER.warn("Failed to parse proxy settings.", ise);
            return false;
        }
    }
}
