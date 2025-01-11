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

import com.github.packageurl.MalformedPackageURLException;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.io.InputStream;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import javax.annotation.concurrent.ThreadSafe;

import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.processing.GrokAssemblyProcessor;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;
import org.owasp.dependencycheck.utils.ExtractionException;
import org.owasp.dependencycheck.utils.ExtractionUtil;
import org.owasp.dependencycheck.utils.processing.ProcessReader;
import org.owasp.dependencycheck.xml.assembly.AssemblyData;
import org.owasp.dependencycheck.xml.assembly.GrokParseException;

/**
 * Analyzer for getting company, product, and version information from a .NET
 * assembly.
 *
 * @author colezlaw
 */
@ThreadSafe
public class AssemblyAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * Logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AssemblyAnalyzer.class);
    /**
     * The analyzer name
     */
    private static final String ANALYZER_NAME = "Assembly Analyzer";
    /**
     * The analysis phase
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;
    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.DOTNET;
    /**
     * The list of supported extensions
     */
    private static final String[] SUPPORTED_EXTENSIONS = {"dll", "exe"};
    /**
     * The File Filter used to filter supported extensions.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(
            SUPPORTED_EXTENSIONS).build();
    /**
     * The file path to `GrokAssembly.dll`.
     */
    private File grokAssembly = null;

    /**
     * The base argument list to call GrokAssembly.
     */
    private List<String> baseArgumentList = null;

    /**
     * Builds the beginnings of a List for ProcessBuilder
     *
     * @return the list of arguments to begin populating the ProcessBuilder
     */
    protected List<String> buildArgumentList() {
        // Use file.separator as a wild guess as to whether this is Windows
        final List<String> args = new ArrayList<>();
        if (!StringUtils.isBlank(getSettings().getString(Settings.KEYS.ANALYZER_ASSEMBLY_DOTNET_PATH))) {
            args.add(getSettings().getString(Settings.KEYS.ANALYZER_ASSEMBLY_DOTNET_PATH));
        } else if (isDotnetPath()) {
            args.add("dotnet");
        } else {
            return null;
        }
        args.add(grokAssembly.getPath());
        return args;
    }

    /**
     * Performs the analysis on a single Dependency.
     *
     * @param dependency the dependency to analyze
     * @param engine the engine to perform the analysis under
     * @throws AnalysisException if anything goes sideways
     */
    @Override
    public void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        final File test = new File(dependency.getActualFilePath());
        if (!test.isFile()) {
            throw new AnalysisException(String.format("%s does not exist and cannot be analyzed by dependency-check",
                    dependency.getActualFilePath()));
        }
        if (grokAssembly == null) {
            LOGGER.warn("GrokAssembly didn't get deployed");
            return;
        }
        if (baseArgumentList == null) {
            LOGGER.warn("Assembly Analyzer was unable to execute");
            return;
        }
        final AssemblyData data;
        final List<String> args = new ArrayList<>(baseArgumentList);
        args.add(dependency.getActualFilePath());
        final ProcessBuilder pb = new ProcessBuilder(args);
        try {
            final Process proc = pb.start();
            try (GrokAssemblyProcessor processor = new GrokAssemblyProcessor();
                    ProcessReader processReader = new ProcessReader(proc, processor)) {
                processReader.readAll();

                final String errorOutput = processReader.getError();
                if (!StringUtils.isBlank(errorOutput)) {
                    LOGGER.warn("Error from GrokAssembly: {}", errorOutput);
                }
                final int exitValue = proc.exitValue();

                if (exitValue == 3) {
                    LOGGER.debug("{} is not a .NET assembly or executable and as such cannot be analyzed by dependency-check",
                            dependency.getActualFilePath());
                    return;
                } else if (exitValue != 0) {
                    LOGGER.debug("Return code {} from GrokAssembly; dependency-check is unable to analyze the library: {}",
                            exitValue, dependency.getActualFilePath());
                    return;
                }
                data = processor.getAssemblyData();
            }
            // First, see if there was an error
            final String error = data.getError();
            if (error != null && !error.isEmpty()) {
                throw new AnalysisException(error);
            }
            if (data.getWarning() != null) {
                LOGGER.debug("Grok Assembly - could not get namespace on dependency `{}` - {}", dependency.getActualFilePath(), data.getWarning());
            }
            updateDependency(data, dependency);
        } catch (GrokParseException saxe) {
            LOGGER.error("----------------------------------------------------");
            LOGGER.error("Failed to read the Assembly Analyzer results.");
            LOGGER.error("----------------------------------------------------");
            throw new AnalysisException("Couldn't parse Assembly Analyzer results (GrokAssembly)", saxe);
        } catch (IOException ioe) {
            throw new AnalysisException(ioe);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new AnalysisException("GrokAssembly process interrupted", ex);
        }
    }

    /**
     * Updates the dependency information with the provided assembly data.
     *
     * @param data the assembly data
     * @param dependency the dependency to update
     */
    private void updateDependency(final AssemblyData data, Dependency dependency) {
        final StringBuilder sb = new StringBuilder();
        if (!StringUtils.isBlank(data.getFileDescription())) {
            sb.append(data.getFileDescription());
        }
        if (!StringUtils.isBlank(data.getComments())) {
            if (sb.length() > 0) {
                sb.append("\n\n");
            }
            sb.append(data.getComments());
        }
        if (!StringUtils.isBlank(data.getLegalCopyright())) {
            if (sb.length() > 0) {
                sb.append("\n\n");
            }
            sb.append(data.getLegalCopyright());
        }
        if (!StringUtils.isBlank(data.getLegalTrademarks())) {
            if (sb.length() > 0) {
                sb.append("\n");
            }
            sb.append(data.getLegalTrademarks());
        }
        final String description = sb.toString();
        if (description.length() > 0) {
            dependency.setDescription(description);
            addMatchingValues(data.getNamespaces(), description, dependency, EvidenceType.VENDOR);
            addMatchingValues(data.getNamespaces(), description, dependency, EvidenceType.PRODUCT);
        }

        if (!StringUtils.isBlank(data.getProductVersion())) {
            dependency.addEvidence(EvidenceType.VERSION, "grokassembly", "ProductVersion", data.getProductVersion(), Confidence.HIGHEST);
        }
        if (!StringUtils.isBlank(data.getFileVersion())) {
            dependency.addEvidence(EvidenceType.VERSION, "grokassembly", "FileVersion", data.getFileVersion(), Confidence.HIGH);
        }

        if (data.getFileVersion() != null && data.getProductVersion() != null) {
            final int max = Math.min(data.getFileVersion().length(), data.getProductVersion().length());
            int pos;
            for (pos = 0; pos < max; pos++) {
                if (data.getFileVersion().charAt(pos) != data.getProductVersion().charAt(pos)) {
                    break;
                }
            }
            final DependencyVersion fileVersion = DependencyVersionUtil.parseVersion(data.getFileVersion(), true);
            final DependencyVersion productVersion = DependencyVersionUtil.parseVersion(data.getProductVersion(), true);
            if (pos > 0) {
                final DependencyVersion matchingVersion = DependencyVersionUtil.parseVersion(data.getFileVersion().substring(0, pos), true);
                if (fileVersion != null && data.getFileVersion() != null
                        && fileVersion.toString().length() == data.getFileVersion().length()) {
                    if (matchingVersion != null && matchingVersion.getVersionParts().size() > 2) {
                        dependency.addEvidence(EvidenceType.VERSION, "AssemblyAnalyzer", "FilteredVersion",
                                matchingVersion.toString(), Confidence.HIGHEST);
                        dependency.setVersion(matchingVersion.toString());
                    }
                }
            }
            if (dependency.getVersion() == null) {
                if (data.getFileVersion() != null && data.getProductVersion() != null
                        && data.getFileVersion().length() >= data.getProductVersion().length()) {
                    if (fileVersion != null && fileVersion.toString().length() == data.getFileVersion().length()) {
                        dependency.setVersion(fileVersion.toString());
                    } else if (productVersion != null && productVersion.toString().length() == data.getProductVersion().length()) {
                        dependency.setVersion(productVersion.toString());
                    }
                } else {
                    if (productVersion != null && productVersion.toString().length() == data.getProductVersion().length()) {
                        dependency.setVersion(productVersion.toString());
                    } else if (fileVersion != null && fileVersion.toString().length() == data.getFileVersion().length()) {
                        dependency.setVersion(fileVersion.toString());
                    }
                }
            }
        }
        if (dependency.getVersion() == null && data.getFileVersion() != null) {
            final DependencyVersion version = DependencyVersionUtil.parseVersion(data.getFileVersion(), true);
            if (version != null) {
                dependency.setVersion(version.toString());
            }
        }
        if (dependency.getVersion() == null && data.getProductVersion() != null) {
            final DependencyVersion version = DependencyVersionUtil.parseVersion(data.getProductVersion(), true);
            if (version != null) {
                dependency.setVersion(version.toString());
            }
        }

        if (!StringUtils.isBlank(data.getCompanyName())) {
            dependency.addEvidence(EvidenceType.VENDOR, "grokassembly", "CompanyName", data.getCompanyName(), Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.PRODUCT, "grokassembly", "CompanyName", data.getCompanyName(), Confidence.LOW);
            addMatchingValues(data.getNamespaces(), data.getCompanyName(), dependency, EvidenceType.VENDOR);
        }
        if (!StringUtils.isBlank(data.getProductName())) {
            dependency.addEvidence(EvidenceType.PRODUCT, "grokassembly", "ProductName", data.getProductName(), Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.VENDOR, "grokassembly", "ProductName", data.getProductName(), Confidence.MEDIUM);
            addMatchingValues(data.getNamespaces(), data.getProductName(), dependency, EvidenceType.PRODUCT);
        }
        if (!StringUtils.isBlank(data.getFileDescription())) {
            dependency.addEvidence(EvidenceType.PRODUCT, "grokassembly", "FileDescription", data.getFileDescription(), Confidence.HIGH);
            dependency.addEvidence(EvidenceType.VENDOR, "grokassembly", "FileDescription", data.getFileDescription(), Confidence.LOW);
            addMatchingValues(data.getNamespaces(), data.getFileDescription(), dependency, EvidenceType.PRODUCT);
        }

        final String internalName = data.getInternalName();
        if (!StringUtils.isBlank(internalName)) {
            dependency.addEvidence(EvidenceType.PRODUCT, "grokassembly", "InternalName", internalName, Confidence.MEDIUM);
            dependency.addEvidence(EvidenceType.VENDOR, "grokassembly", "InternalName", internalName, Confidence.LOW);
            addMatchingValues(data.getNamespaces(), internalName, dependency, EvidenceType.PRODUCT);
            addMatchingValues(data.getNamespaces(), internalName, dependency, EvidenceType.VENDOR);
            if (dependency.getName() == null && StringUtils.containsIgnoreCase(dependency.getActualFile().getName(), internalName)) {
                final String ext = FileUtils.getFileExtension(internalName);
                if (ext != null) {
                    dependency.setName(internalName.substring(0, internalName.length() - ext.length() - 1));
                } else {
                    dependency.setName(internalName);
                }
            }
        }

        final String originalFilename = data.getOriginalFilename();
        if (!StringUtils.isBlank(originalFilename)) {
            dependency.addEvidence(EvidenceType.PRODUCT, "grokassembly", "OriginalFilename", originalFilename, Confidence.MEDIUM);
            dependency.addEvidence(EvidenceType.VENDOR, "grokassembly", "OriginalFilename", originalFilename, Confidence.LOW);
            addMatchingValues(data.getNamespaces(), originalFilename, dependency, EvidenceType.PRODUCT);
            if (dependency.getName() == null && StringUtils.containsIgnoreCase(dependency.getActualFile().getName(), originalFilename)) {
                final String ext = FileUtils.getFileExtension(originalFilename);
                if (ext != null) {
                    dependency.setName(originalFilename.substring(0, originalFilename.length() - ext.length() - 1));
                } else {
                    dependency.setName(originalFilename);
                }
            }
        }
        if (dependency.getName() != null && dependency.getVersion() != null) {
            try {
                dependency.addSoftwareIdentifier(new PurlIdentifier("generic", dependency.getName(), dependency.getVersion(), Confidence.MEDIUM));
            } catch (MalformedPackageURLException ex) {
                LOGGER.debug("Unable to create Package URL Identifier for " + dependency.getName(), ex);
                dependency.addSoftwareIdentifier(new GenericIdentifier(
                        String.format("%s@%s", dependency.getName(), dependency.getVersion()),
                        Confidence.MEDIUM));
            }
        }
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
    }

    /**
     * Initialize the analyzer. In this case, extract GrokAssembly.dll to a
     * temporary location.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException thrown if anything goes wrong
     */
    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        grokAssembly = extractGrokAssembly();

        baseArgumentList = buildArgumentList();
        if (baseArgumentList == null) {
            setEnabled(false);
            LOGGER.error("----------------------------------------------------");
            LOGGER.error(".NET Assembly Analyzer could not be initialized and at least one "
                    + "'exe' or 'dll' was scanned. The 'dotnet' executable could not be found on "
                    + "the path; either disable the Assembly Analyzer or add the path to dotnet "
                    + "core in the configuration.");
            LOGGER.error("The dotnet 8.0 core runtime or SDK is required to analyze assemblies");
            LOGGER.error("----------------------------------------------------");
            return;
        }
        try {
            final ProcessBuilder pb = new ProcessBuilder(baseArgumentList);
            final Process p = pb.start();
            try (ProcessReader processReader = new ProcessReader(p)) {
                processReader.readAll();
                final String error = processReader.getError();
                if (p.exitValue() != 1 || !StringUtils.isBlank(error)) {
                    LOGGER.warn("An error occurred with the .NET AssemblyAnalyzer, please see the log for more details.\n"
                    + "dependency-check requires dotnet 8.0 core runtime or sdk to be installed to analyze assemblies.");
                    LOGGER.debug("GrokAssembly.dll is not working properly");
                    grokAssembly = null;
                    setEnabled(false);
                    throw new InitializationException("Could not execute .NET AssemblyAnalyzer, is the dotnet 8.0 runtime or sdk installed?");
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("An error occurred with the .NET AssemblyAnalyzer;\n"
                    + "dependency-check requires dotnet 8.0 core runtime or sdk to be installed to analyze assemblies;\n"
                    + "this can be ignored unless you are scanning .NET DLLs. Please see the log for more details.");
            LOGGER.debug("Could not execute GrokAssembly {}", e.getMessage());
            setEnabled(false);
            throw new InitializationException("An error occurred with the .NET AssemblyAnalyzer", e);
        } catch (IOException e) {
            LOGGER.warn("An error occurred with the .NET AssemblyAnalyzer;\n"
                    + "dependency-check requires dotnet 8.0 core to be installed to analyze assemblies;\n"
                    + "this can be ignored unless you are scanning .NET DLLs. Please see the log for more details.");
            LOGGER.debug("Could not execute GrokAssembly {}", e.getMessage());
            setEnabled(false);
            throw new InitializationException("An error occurred with the .NET AssemblyAnalyzer, is the dotnet 8.0 runtime or sdk installed?", e);
        }
    }

    /**
     * Extracts the GrokAssembly executable.
     *
     * @return the path to the extracted executable
     * @throws InitializationException thrown if the executable could not be
     * extracted
     */
    private File extractGrokAssembly() throws InitializationException {
        final File location;
        try (InputStream in = FileUtils.getResourceAsStream("GrokAssembly.zip")) {
            if (in == null) {
                throw new InitializationException("Unable to extract GrokAssembly.dll - file not found");
            }
            location = FileUtils.createTempDirectory(getSettings().getTempDirectory());
            ExtractionUtil.extractFiles(in, location);
        } catch (ExtractionException ex) {
            throw new InitializationException("Unable to extract GrokAssembly.dll", ex);
        } catch (IOException ex) {
            throw new InitializationException("Unable to create temp directory for GrokAssembly", ex);
        }
        return new File(location, "GrokAssembly.dll");
    }

    /**
     * Removes resources used from the local file system.
     *
     * @throws Exception thrown if there is a problem closing the analyzer
     */
    @Override
    public void closeAnalyzer() throws Exception {
        FileUtils.delete(grokAssembly.getParentFile());
    }

    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * Gets this analyzer's name.
     *
     * @return the analyzer name
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the phase this analyzer runs under.
     *
     * @return the phase this runs under
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
        return Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED;
    }

    /**
     * Tests to see if a file is in the system path.
     *
     * @return <code>true</code> if dotnet could be found in the path; otherwise
     * <code>false</code>
     */
    private boolean isDotnetPath() {
        final String[] args = new String[2];
        args[0] = "dotnet";
        args[1] = "--info";
        final ProcessBuilder pb = new ProcessBuilder(args);
        try {
            final Process proc = pb.start();
            try (ProcessReader processReader = new ProcessReader(proc)) {
                processReader.readAll();
                final int exitValue = proc.exitValue();
                if (exitValue == 0) {
                    return true;
                }
                final String output = processReader.getOutput();
                if (output.length() > 0) {
                    return true;
                }
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            LOGGER.debug("Path search failed for dotnet", ex);
        } catch (IOException ex) {
            LOGGER.debug("Path search failed for dotnet", ex);
        }
        return false;
    }

    /**
     * Cycles through the collection of class name information to see if parts
     * of the package names are contained in the provided value. If found, it
     * will be added as the HIGHEST confidence evidence because we have more
     * then one source corroborating the value.
     *
     * @param packages a collection of class name information
     * @param value the value to check to see if it contains a package name
     * @param dep the dependency to add new entries too
     * @param type the type of evidence (vendor, product, or version)
     */
    protected static void addMatchingValues(List<String> packages, String value, Dependency dep, EvidenceType type) {
        if (value == null || value.isEmpty() || packages == null || packages.isEmpty()) {
            return;
        }
        for (String key : packages) {
            final int pos = StringUtils.indexOfIgnoreCase(value, key);
            if ((pos == 0 && (key.length() == value.length() || (key.length() < value.length()
                    && !Character.isLetterOrDigit(value.charAt(key.length())))))
                    || (pos > 0 && !Character.isLetterOrDigit(value.charAt(pos - 1))
                    && (pos + key.length() == value.length() || (key.length() < value.length()
                    && !Character.isLetterOrDigit(value.charAt(pos + key.length())))))) {
                dep.addEvidence(type, "dll", "namespace", key, Confidence.HIGHEST);
            }

        }
    }

    /**
     * Used in testing only - this simply returns the path to the extracted
     * GrokAssembly.dll.
     *
     * @return the path to the extracted GrokAssembly.dll
     */
    File getGrokAssemblyPath() {
        return grokAssembly;
    }
}
