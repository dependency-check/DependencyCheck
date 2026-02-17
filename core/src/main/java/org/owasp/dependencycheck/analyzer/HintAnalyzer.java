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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.google.common.annotations.VisibleForTesting;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import org.owasp.dependencycheck.xml.hints.EvidenceMatcher;
import org.owasp.dependencycheck.xml.hints.HintParseException;
import org.owasp.dependencycheck.xml.hints.HintParser;
import org.owasp.dependencycheck.xml.hints.HintRule;
import org.owasp.dependencycheck.xml.hints.VendorDuplicatingHintRule;
import org.owasp.dependencycheck.xml.suppression.PropertyType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import javax.annotation.concurrent.ThreadSafe;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * This analyzer adds evidence to dependencies to enhance the accuracy of
 * library identification.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class HintAnalyzer extends AbstractAnalyzer {

    /**
     * The Logger for use throughout the class
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(HintAnalyzer.class);
    /**
     * The name of the hint rule file
     */
    private static final String HINT_RULE_FILE_NAME = "dependencycheck-base-hint.xml";
    /**
     * The array of hint rules.
     */
    private HintRule[] hints = null;
    /**
     * The array of vendor duplicating hint rules.
     */
    private VendorDuplicatingHintRule[] vendorHints;
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Hint Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.POST_INFORMATION_COLLECTION2;

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
     * <p>
     * Returns the setting key to determine if the analyzer is enabled.</p>
     *
     * @return the key for the analyzer's enabled property
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_HINT_ENABLED;
    }

    /**
     * The prepare method does nothing for this Analyzer.
     *
     * @param engine a reference the dependency-check engine
     * @throws InitializationException thrown if there is an exception
     */
    @Override
    public void prepareAnalyzer(Engine engine) throws InitializationException {
        try {
            loadHintRules();
        } catch (HintParseException ex) {
            LOGGER.debug("Unable to parse hint file", ex);
            throw new InitializationException("Unable to parse the hint file", ex);
        }
    }

    /**
     * The HintAnalyzer uses knowledge about a dependency to add additional
     * information to help in identification of identifiers or vulnerabilities.
     *
     * @param dependency The dependency being analyzed
     * @param engine The scanning engine
     * @throws AnalysisException is thrown if there is an exception analyzing
     * the dependency.
     */
    @Override
    @SuppressWarnings("StringSplitter")
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        for (HintRule hint : hints) {
            boolean matchFound = false;
            for (EvidenceMatcher given : hint.getGivenVendor()) {
                if (hasMatchingEvidence(dependency.getEvidence(EvidenceType.VENDOR), given)) {
                    matchFound = true;
                    break;
                }
            }
            if (!matchFound) {
                for (EvidenceMatcher given : hint.getGivenProduct()) {
                    if (hasMatchingEvidence(dependency.getEvidence(EvidenceType.PRODUCT), given)) {
                        matchFound = true;
                        break;
                    }
                }
            }
            if (!matchFound) {
                for (EvidenceMatcher given : hint.getGivenVersion()) {
                    if (hasMatchingEvidence(dependency.getEvidence(EvidenceType.VERSION), given)) {
                        matchFound = true;
                        break;
                    }
                }
            }
            if (!matchFound) {
                for (PropertyType pt : hint.getFileNames()) {
                    if (pt.matches(dependency.getFileName())) {
                        matchFound = true;
                        break;
                    }
                }
            }
            if (matchFound) {
                hint.getAddVendor().forEach((e) -> {
                    dependency.addEvidence(EvidenceType.VENDOR, e);
                    for (String weighting : e.getValue().split(" ")) {
                        dependency.addVendorWeighting(weighting);
                    }
                });
                hint.getAddProduct().forEach((e) -> {
                    dependency.addEvidence(EvidenceType.PRODUCT, e);
                    for (String weighting : e.getValue().split(" ")) {
                        dependency.addProductWeighting(weighting);
                    }
                });
                hint.getAddVersion().forEach((e) -> dependency.addEvidence(EvidenceType.VERSION, e));

                hint.getRemoveVendor().forEach((e) -> removeMatchingEvidences(dependency, EvidenceType.VENDOR, e));
                hint.getRemoveProduct().forEach((e) -> removeMatchingEvidences(dependency, EvidenceType.PRODUCT, e));
                hint.getRemoveVersion().forEach((e) -> removeMatchingEvidences(dependency, EvidenceType.VERSION, e));
            }
        }

        for (Evidence e : dependency.getEvidence(EvidenceType.VENDOR)) {
            for (VendorDuplicatingHintRule dhr : vendorHints) {
                if (dhr.getValue().equalsIgnoreCase(e.getValue())) {
                    dependency.addEvidence(EvidenceType.VENDOR, new Evidence(e.getSource() + " (hint)",
                            e.getName(), dhr.getDuplicate(), e.getConfidence(), true));
                }
            }
        }
    }

    /**
     * Determine if there is matching evidence.
     *
     * @param evidences the evidence to test
     * @param criterion the criteria for a match
     * @return true if the evidence matches, otherwise false
     */
    private boolean hasMatchingEvidence(Set<Evidence> evidences, EvidenceMatcher criterion) {
        for (Evidence evidence : evidences) {
            if (criterion.matches(evidence)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Removes any matching evidence from the dependency.
     *
     * @param dependency the dependency to update
     * @param type the type of evidence to inspect and possibly remove
     * @param e the evidence matcher
     */
    private void removeMatchingEvidences(Dependency dependency, EvidenceType type, EvidenceMatcher e) {
        for (Evidence evidence : dependency.getEvidence(type)) {
            if (e.matches(evidence)) {
                dependency.removeEvidence(type, evidence);
            }
        }
    }

    /**
     * Loads the hint rules file.
     *
     * @throws HintParseException thrown if the XML cannot be parsed.
     */
    private void loadHintRules() throws HintParseException {
        final List<HintRule> localHints;
        final List<VendorDuplicatingHintRule> localVendorHints;
        final HintParser parser = new HintParser();
        File file = null;
        try (InputStream in = FileUtils.getResourceAsStream(HINT_RULE_FILE_NAME)) {
            parser.parseHints(in);
        } catch (SAXException | IOException ex) {
            throw new HintParseException("Error parsing hints: " + ex.getMessage(), ex);
        }
        localHints = parser.getHintRules();
        localVendorHints = parser.getVendorDuplicatingHintRules();

        final String filePath = getSettings().getString(Settings.KEYS.HINTS_FILE);
        if (filePath != null) {
            boolean deleteTempFile = false;
            try {
                final Pattern uriRx = Pattern.compile("^(https?|file):.*", Pattern.CASE_INSENSITIVE);
                if (uriRx.matcher(filePath).matches()) {
                    deleteTempFile = true;
                    file = getSettings().getTempFile("hint", "xml");
                    final URL url = new URL(filePath);
                    try {
                        Downloader.getInstance().fetchFile(url, file, false);
                    } catch (DownloadFailedException ex) {
                        try {
                            Thread.sleep(500);
                            Downloader.getInstance().fetchFile(url, file, true);
                        } catch (TooManyRequestsException ex1) {
                            throw new HintParseException("Unable to download hint file `" + file + "`; received 429 - too many requests", ex1);
                        } catch (ResourceNotFoundException ex1) {
                            throw new HintParseException("Unable to download hint file `" + file + "`; received 404 - resource not found", ex1);
                        } catch (InterruptedException ex1) {
                            Thread.currentThread().interrupt();
                            throw new HintParseException("Unable to download hint file `" + file + "`", ex1);
                        }
                    } catch (TooManyRequestsException ex) {
                        throw new HintParseException("Unable to download hint file `" + file + "`; received 429 - too many requests", ex);
                    } catch (ResourceNotFoundException ex) {
                        throw new HintParseException("Unable to download hint file `" + file + "`; received 404 - resource not found", ex);
                    }
                } else {
                    file = new File(filePath);
                    if (!file.exists()) {
                        try (InputStream fromClasspath = FileUtils.getResourceAsStream(filePath)) {
                            deleteTempFile = true;
                            file = getSettings().getTempFile("hint", "xml");
                            Files.copy(fromClasspath, file.toPath());
                        } catch (IOException ex) {
                            throw new HintParseException("Unable to locate hints file in classpath", ex);
                        }
                    }
                }

                try {
                    parser.parseHints(file);
                    if (parser.getHintRules() != null && !parser.getHintRules().isEmpty()) {
                        localHints.addAll(parser.getHintRules());
                    }
                    if (parser.getVendorDuplicatingHintRules() != null && !parser.getVendorDuplicatingHintRules().isEmpty()) {
                        localVendorHints.addAll(parser.getVendorDuplicatingHintRules());
                    }
                } catch (HintParseException ex) {
                    LOGGER.warn("Unable to parse hint rule xml file '{}'", file.getPath());
                    LOGGER.warn(ex.getMessage());
                    LOGGER.debug("", ex);
                    throw ex;
                }
            } catch (DownloadFailedException ex) {
                throw new HintParseException("Unable to fetch the configured hint file", ex);
            } catch (MalformedURLException ex) {
                throw new HintParseException("Configured hint file has an invalid URL", ex);
            } catch (IOException ex) {
                throw new HintParseException("Unable to create temp file for hints", ex);
            } finally {
                if (deleteTempFile && file != null) {
                    FileUtils.delete(file);
                }
            }
        }
        hints = localHints.toArray(new HintRule[0]);
        vendorHints = localVendorHints.toArray(new VendorDuplicatingHintRule[0]);
        LOGGER.debug("{} hint rules were loaded.", hints.length);
        LOGGER.debug("{} duplicating hint rules were loaded.", vendorHints.length);
    }

    @VisibleForTesting
    HintRule[] getHintRules() {
        return hints;
    }

    @VisibleForTesting
    VendorDuplicatingHintRule[] getVendorDuplicatingHintRules() {
        return vendorHints;
    }
}
