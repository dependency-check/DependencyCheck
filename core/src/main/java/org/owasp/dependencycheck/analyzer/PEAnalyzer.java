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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;

import org.boris.pecoff4j.PE;
import org.boris.pecoff4j.ResourceDirectory;
import org.boris.pecoff4j.ResourceEntry;
import org.boris.pecoff4j.constant.ResourceType;
import org.owasp.dependencycheck.utils.PEParser;
import org.boris.pecoff4j.io.ResourceParser;
import org.boris.pecoff4j.resources.StringFileInfo;
import org.boris.pecoff4j.resources.StringTable;
import org.boris.pecoff4j.resources.VersionInfo;
import org.boris.pecoff4j.util.ResourceHelper;

import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.lang3.StringUtils;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Takes a dependency and analyze the PE header for meta data that can be used
 * to identify the library.
 *
 * @author Amodio Pesce
 */
@ThreadSafe
@Experimental
public class PEAnalyzer extends AbstractFileTypeAnalyzer {

    //<editor-fold defaultstate="collapsed" desc="All standard implementation details of Analyzer">
    /**
     * Logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AssemblyAnalyzer.class);
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "PE Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION2;
    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final String[] EXTENSIONS = {"exe", "dll"};

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(EXTENSIONS).build();
    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.NATIVE;

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
        return Settings.KEYS.ANALYZER_PE_ENABLED;
    }

    /**
     * Returns the FileFilter.
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        //nothing to prepare
    }

    /**
     * Collects information about the file name.
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error analyzing the PE
     * file.
     */
    @Override
    protected void analyzeDependency(final Dependency dependency, final Engine engine) throws AnalysisException {
        for (Evidence e : dependency.getEvidence()) {
            if ("grokassembly".equals(e.getSource())) {
                LOGGER.debug("Skipping {} because it was already analyzed by the Assembly Analyzer", dependency.getFileName());
                return;
            }
        }
        try {
            final File fileToCheck = dependency.getActualFile();
            final PE pe = PEParser.parse(fileToCheck.getPath());
            final ResourceDirectory rd = pe.getImageData().getResourceTable();
            final ResourceEntry[] entries = ResourceHelper.findResources(rd, ResourceType.VERSION_INFO);
            for (ResourceEntry entrie : entries) {
                final byte[] data = entrie.getData();
                final VersionInfo version = ResourceParser.readVersionInfo(data);
                final StringFileInfo strings = version.getStringFileInfo();
                final StringTable table = strings.getTable(0);
                String pVersion = null;
                String fVersion = null;

                for (int j = 0; j < table.getCount(); j++) {
                    final String key = table.getString(j).getKey();
                    final String value = table.getString(j).getValue();
                    switch (key) {
                        case "ProductVersion":
                            dependency.addEvidence(EvidenceType.VERSION, "PE Header", "ProductVersion", value, Confidence.HIGHEST);
                            pVersion = value;
                            break;
                        case "CompanyName":
                            dependency.addEvidence(EvidenceType.VENDOR, "PE Header", "CompanyName", value, Confidence.HIGHEST);
                            break;
                        case "FileVersion":
                            dependency.addEvidence(EvidenceType.VERSION, "PE Header", "FileVersion", value, Confidence.HIGH);
                            fVersion = value;
                            break;
                        case "InternalName":
                            dependency.addEvidence(EvidenceType.PRODUCT, "PE Header", "InternalName", value, Confidence.MEDIUM);
                            dependency.addEvidence(EvidenceType.VENDOR, "PE Header", "InternalName", value, Confidence.LOW);
                            determineDependencyName(dependency, value);
                            break;
                        case "LegalCopyright":
                            dependency.addEvidence(EvidenceType.VENDOR, "PE Header", "LegalCopyright", value, Confidence.HIGHEST);
                            if (dependency.getLicense() != null && dependency.getLicense().length() > 0) {
                                dependency.setLicense(dependency.getLicense() + "/n/nLegal Copyright: " + value);
                            } else {
                                dependency.setLicense("Legal Copyright: " + value);
                            }
                            break;
                        case "OriginalFilename":
                            dependency.addEvidence(EvidenceType.VERSION, "PE Header", "OriginalFilename", value, Confidence.MEDIUM);
                            determineDependencyName(dependency, value);
                            break;
                        case "ProductName":
                            dependency.addEvidence(EvidenceType.PRODUCT, "PE Header", "ProductName", value, Confidence.HIGHEST);
                            dependency.addEvidence(EvidenceType.VENDOR, "PE Header", "ProductName", value, Confidence.MEDIUM);
                            determineDependencyName(dependency, value);
                            break;
                        default:
                            LOGGER.debug("PE Analyzer found `" + key + "` with a value:" + value);
                    }
                    if (fVersion != null && pVersion != null) {
                        final int max = Math.min(fVersion.length(), pVersion.length());
                        int pos;
                        for (pos = 0; pos < max; pos++) {
                            if (fVersion.charAt(pos) != pVersion.charAt(pos)) {
                                break;
                            }
                        }
                        final DependencyVersion fileVersion = DependencyVersionUtil.parseVersion(fVersion, true);
                        final DependencyVersion productVersion = DependencyVersionUtil.parseVersion(pVersion, true);
                        if (pos > 0) {
                            final DependencyVersion matchingVersion = DependencyVersionUtil.parseVersion(fVersion.substring(0, pos), true);
                            if (fileVersion != null && fileVersion.toString().length() == fVersion.length()) {
                                if (matchingVersion != null && matchingVersion.getVersionParts().size() > 2) {
                                    dependency.addEvidence(EvidenceType.VERSION, "PE Header", "FilteredVersion",
                                            matchingVersion.toString(), Confidence.HIGHEST);
                                    dependency.setVersion(matchingVersion.toString());
                                }
                            }
                        }
                        if (dependency.getVersion() == null) {
                            if (fVersion.length() >= pVersion.length()) {
                                if (fileVersion != null && fileVersion.toString().length() == fVersion.length()) {
                                    dependency.setVersion(fileVersion.toString());
                                } else if (productVersion != null && productVersion.toString().length() == pVersion.length()) {
                                    dependency.setVersion(productVersion.toString());
                                }
                            } else {
                                if (productVersion != null && productVersion.toString().length() == pVersion.length()) {
                                    dependency.setVersion(productVersion.toString());
                                } else if (fileVersion != null && fileVersion.toString().length() == fVersion.length()) {
                                    dependency.setVersion(fileVersion.toString());
                                }
                            }
                        }
                    } else if (pVersion != null) {
                        final DependencyVersion productVersion = DependencyVersionUtil.parseVersion(pVersion, true);
                        if (productVersion != null && dependency.getActualFile().getName().contains(productVersion.toString())) {
                            dependency.setVersion(productVersion.toString());
                        }
                    } else if (fVersion != null) {
                        final DependencyVersion fileVersion = DependencyVersionUtil.parseVersion(fVersion, true);
                        if (fileVersion != null && dependency.getActualFile().getName().contains(fileVersion.toString())) {
                            dependency.setVersion(fileVersion.toString());
                        }
                    }
                    if (dependency.getName() != null && dependency.getVersion() != null) {
                        try {
                            dependency.addSoftwareIdentifier(new PurlIdentifier("generic", dependency.getName(),
                                    dependency.getVersion(), Confidence.MEDIUM));
                        } catch (MalformedPackageURLException ex) {
                            LOGGER.debug("Unable to create Package URL Identifier for " + dependency.getName(), ex);
                            dependency.addSoftwareIdentifier(new GenericIdentifier(
                                    String.format("%s@%s", dependency.getName(), dependency.getVersion()),
                                    Confidence.MEDIUM));
                        }
                    }
                    if (dependency.getEcosystem() == null) {
                        //this could be an assembly
                        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
                    }
                }
            }
        } catch (IOException ex) {
            throw new AnalysisException(ex);
        }
    }

    private void determineDependencyName(final Dependency dependency, final String value) {
        if (dependency.getName() == null && StringUtils.containsIgnoreCase(dependency.getActualFile().getName(), value)) {
            final String ext = FileUtils.getFileExtension(value);
            if (ext != null) {
                dependency.setName(value.substring(0, value.length() - ext.length() - 1));
            } else {
                dependency.setName(value);
            }
        }
    }
}
