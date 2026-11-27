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
 * Copyright (c) 2015 Institute for Defense Analyses. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.apache.commons.io.filefilter.NameFileFilter;
import org.apache.commons.io.filefilter.SuffixFileFilter;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.ExtractionException;
import org.owasp.dependencycheck.utils.ExtractionUtil;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.PyPACoreMetadataParser;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.UrlStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Used to analyze a Wheel or egg distribution files, or their contents in
 * unzipped form, and collect information that can be used to determine the
 * associated CPE.
 *
 * @author Dale Visser
 */
@Experimental
@ThreadSafe
public class PythonDistributionAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.PYTHON;

    /**
     * Name of egg metadata files to analyze.
     */
    private static final String PKG_INFO = "PKG-INFO";
    /**
     * Name of wheel metadata files to analyze.
     */
    private static final String METADATA = "METADATA";
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(PythonDistributionAnalyzer.class);
    /**
     * The count of directories created during analysis. This is used for
     * creating temporary directories.
     */
    private static final AtomicInteger DIR_COUNT = new AtomicInteger(0);
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Python Distribution Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;
    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final String[] EXTENSIONS = {"whl", "egg", "zip"};
    /**
     * Used to match on egg archive candidate extensions.
     */
    private static final FileFilter EGG_OR_ZIP = FileFilterBuilder.newInstance().addExtensions("egg", "zip").build();
    /**
     * Used to detect files with a .whl extension.
     */
    private static final FileFilter WHL_FILTER = FileFilterBuilder.newInstance().addExtensions("whl").build();
    /**
     * The parent directory for the individual directories per archive.
     */
    private File tempFileLocation;
    /**
     * Filter that detects *.dist-info files (but doesn't verify they are
     * directories.
     */
    private static final FilenameFilter DIST_INFO_FILTER = new SuffixFileFilter(".dist-info");
    /**
     * Filter that detects files named "METADATA".
     */
    private static final FilenameFilter EGG_INFO_FILTER = new NameFileFilter("EGG-INFO");
    /**
     * Filter that detects files named "METADATA".
     */
    private static final NameFileFilter METADATA_FILTER = new NameFileFilter(METADATA);
    /**
     * Filter that detects files named "PKG-INFO".
     */
    private static final NameFileFilter PKG_INFO_FILTER = new NameFileFilter(PKG_INFO);
    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFileFilters(
            METADATA_FILTER, PKG_INFO_FILTER).addExtensions(EXTENSIONS).build();

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
        return Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine)
            throws AnalysisException {

        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
        final File actualFile = dependency.getActualFile();
        if (WHL_FILTER.accept(actualFile)) {
            collectMetadataFromArchiveFormat(dependency, DIST_INFO_FILTER,
                    METADATA_FILTER);
        } else if (EGG_OR_ZIP.accept(actualFile)) {
            collectMetadataFromArchiveFormat(dependency, EGG_INFO_FILTER,
                    PKG_INFO_FILTER);
        } else {
            final String name = actualFile.getName();
            final boolean metadata = METADATA.equals(name);
            if (metadata || PKG_INFO.equals(name)) {
                final File parent = actualFile.getParentFile();
                final String parentName = parent.getName();
                if (parent.isDirectory()
                        && ((metadata && parentName.endsWith(".dist-info"))
                        || parentName.endsWith(".egg-info") || "EGG-INFO"
                        .equals(parentName))) {
                    collectWheelMetadata(dependency, actualFile);
                }
            }
        }
    }

    /**
     * Collects the meta data from an archive.
     *
     * @param dependency the archive being scanned
     * @param folderFilter the filter to apply to the folder
     * @param metadataFilter the filter to apply to the meta data
     * @throws AnalysisException thrown when there is a problem analyzing the
     * dependency
     */
    private void collectMetadataFromArchiveFormat(Dependency dependency,
            FilenameFilter folderFilter, FilenameFilter metadataFilter)
            throws AnalysisException {
        final File temp = getNextTempDirectory();
        LOGGER.debug("{} exists? {}", temp, temp.exists());
        try {
            ExtractionUtil.extractFilesUsingFilter(
                    new File(dependency.getActualFilePath()), temp,
                    metadataFilter);
        } catch (ExtractionException ex) {
            throw new AnalysisException(ex);
        }

        File matchingFile = getMatchingFile(temp, folderFilter);
        if (matchingFile != null) {
            matchingFile = getMatchingFile(matchingFile, metadataFilter);
            if (matchingFile != null) {
                collectWheelMetadata(dependency, matchingFile);
            }
        }
    }

    /**
     * Makes sure a usable temporary directory is available.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException an AnalyzeException is thrown when the
     * temp directory cannot be created
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        try {
            final File baseDir = getSettings().getTempDirectory();
            tempFileLocation = File.createTempFile("check", "tmp", baseDir);
            if (!tempFileLocation.delete()) {
                setEnabled(false);
                final String msg = String.format(
                        "Unable to delete temporary file '%s'.",
                        tempFileLocation.getAbsolutePath());
                throw new InitializationException(msg);
            }
            if (!tempFileLocation.mkdirs()) {
                setEnabled(false);
                final String msg = String.format(
                        "Unable to create directory '%s'.",
                        tempFileLocation.getAbsolutePath());
                throw new InitializationException(msg);
            }
        } catch (IOException ex) {
            setEnabled(false);
            throw new InitializationException("Unable to create a temporary file", ex);
        }
    }

    /**
     * Deletes any files extracted from the Wheel during analysis.
     */
    @Override
    public void closeAnalyzer() {
        if (tempFileLocation != null && tempFileLocation.exists()) {
            LOGGER.debug("Attempting to delete temporary files");
            final boolean success = FileUtils.delete(tempFileLocation);
            if (!success && tempFileLocation.exists()) {
                final String[] l = tempFileLocation.list();
                if (l != null && l.length > 0) {
                    LOGGER.warn("Failed to delete some temporary files, see the log for more details");
                }
            }
        }
    }

    /**
     * Gathers evidence from the METADATA file.
     *
     * @param dependency the dependency being analyzed
     * @param file a reference to the manifest/properties file
     */
    private void collectWheelMetadata(Dependency dependency, File file) throws AnalysisException {
        final Properties headers = PyPACoreMetadataParser.getProperties(file);
        final String version = addPropertyToEvidence(dependency, EvidenceType.VERSION, Confidence.HIGHEST, headers, "Version");
        final String name = addPropertyToEvidence(dependency, EvidenceType.VENDOR, Confidence.HIGHEST, headers, "Name");
        addPropertyToEvidence(dependency, EvidenceType.PRODUCT, Confidence.HIGHEST, headers, "Name");

        final String packagePath = String.format("%s:%s", name, version);
        dependency.setName(name);
        dependency.setVersion(version);
        dependency.setPackagePath(packagePath);
        dependency.setDisplayFileName(packagePath);
        final String url = headers.getProperty("Home-page", null);
        if (StringUtils.isNotBlank(url)) {
            if (UrlStringUtils.isUrl(url)) {
                dependency.addEvidence(EvidenceType.VENDOR, METADATA, "vendor", url, Confidence.MEDIUM);
            }
        }
        addPropertyToEvidence(dependency, EvidenceType.VENDOR, Confidence.LOW, headers, "Author");
        final String summary = headers.getProperty("Summary", null);
        if (StringUtils.isNotBlank(summary)) {
            dependency.setDescriptionSanitized(summary);
        }

        try {
            final PackageURL purl = PackageURLBuilder.aPackageURL().withType("pypi")
                    .withName(name).withVersion(version).build();
            dependency.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
        } catch (MalformedPackageURLException ex) {
            LOGGER.debug("Unable to build package url for python", ex);
            final GenericIdentifier id = new GenericIdentifier("generic:" + name + "@" + version, Confidence.HIGHEST);
            dependency.addSoftwareIdentifier(id);
        }
    }

    /**
     * Adds a value to the evidence collection.
     *
     * @param dependency the dependency being analyzed
     * @param type the type of evidence to add
     * @param confidence the confidence in the evidence being added
     * @param headers the properties collection
     * @param property the property name
     * @return returns the value of the property if found; otherwise
     * <code>null</code>
     */
    private static String addPropertyToEvidence(Dependency dependency, EvidenceType type, Confidence confidence,
            Properties headers, String property) {
        final String value = headers.getProperty(property, null);
        LOGGER.debug("Property: {}, Value: {}", property, value);
        if (StringUtils.isNotBlank(value)) {
            dependency.addEvidence(type, METADATA, property, value, confidence);
        }
        return value;
    }

    /**
     * Returns a list of files that match the given filter, this does not
     * recursively scan the directory.
     *
     * @param folder the folder to filter
     * @param filter the filter to apply to the files in the directory
     * @return the list of Files in the directory that match the provided filter
     */
    private static File getMatchingFile(File folder, FilenameFilter filter) {
        File result = null;
        final File[] matches = folder.listFiles(filter);
        if (null != matches && 1 == matches.length) {
            result = matches[0];
        }
        return result;
    }

    /**
     * Reads the manifest entries from the provided file.
     *
     * @param manifest the manifest
     * @return the manifest entries
     */
    private static Properties getManifestProperties(File manifest) {
        final Properties prop = new Properties();
        if (null == manifest) {
            LOGGER.debug("Manifest file not found.");
        } else {
            try (InputStream in = new BufferedInputStream(new FileInputStream(manifest))) {
                prop.load(in);
            } catch (IOException e) {
                LOGGER.warn(e.getMessage(), e);
            }
        }
        return prop;
    }

    /**
     * Retrieves the next temporary destination directory for extracting an
     * archive.
     *
     * @return a directory
     * @throws AnalysisException thrown if unable to create temporary directory
     */
    private File getNextTempDirectory() throws AnalysisException {
        File directory;

        // getting an exception for some directories not being able to be
        // created; might be because the directory already exists?
        do {
            final int dirCount = DIR_COUNT.incrementAndGet();
            directory = new File(tempFileLocation, String.valueOf(dirCount));
        } while (directory.exists());
        if (!directory.mkdirs()) {
            throw new AnalysisException(String.format(
                    "Unable to create temp directory '%s'.",
                    directory.getAbsolutePath()));
        }
        return directory;
    }
}
