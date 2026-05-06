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
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Used to analyze OpenSSL source code present in the file system.
 *
 * @author Dale Visser
 */
@ThreadSafe
public class OpenSSLAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(OpenSSLAnalyzer.class);
    /**
     * Hexadecimal.
     */
    private static final int HEXADECIMAL = 16;
    /**
     * Filename to analyze. All other .h files get removed from consideration.
     */
    private static final String OPENSSLV_H = "opensslv.h";

    /**
     * Filter that detects files named "__init__.py".
     */
    private static final FileFilter OPENSSLV_FILTER = FileFilterBuilder.newInstance().addFilenames(OPENSSLV_H).build();
    /**
     * Open SSL Version number pattern (OpenSSL 1.x and earlier — literal hex constant).
     */
    private static final Pattern VERSION_PATTERN = Pattern.compile(
            "define\\s+OPENSSL_VERSION_NUMBER\\s+0x([0-9a-zA-Z]{8})L", Pattern.DOTALL
                    | Pattern.CASE_INSENSITIVE);
    /**
     * Open SSL version string pattern (OpenSSL 3.x — {@code OPENSSL_VERSION_STR "X.Y.Z"}).
     * In 3.x, {@code OPENSSL_VERSION_NUMBER} is a macro expression that the
     * legacy {@link #VERSION_PATTERN} cannot match, so this is the authoritative
     * source of the version on 3.x headers.
     */
    private static final Pattern VERSION_STR_PATTERN = Pattern.compile(
            "define\\s+OPENSSL_VERSION_STR\\s+\"([^\"]+)\"", Pattern.DOTALL
                    | Pattern.CASE_INSENSITIVE);
    /**
     * The offset of the major version number.
     */
    private static final int MAJOR_OFFSET = 28;
    /**
     * The mask for the minor version number.
     */
    private static final long MINOR_MASK = 0x0ff00000L;
    /**
     * The offset of the minor version number.
     */
    private static final int MINOR_OFFSET = 20;
    /**
     * The max for the fix version.
     */
    private static final long FIX_MASK = 0x000ff000L;
    /**
     * The offset for the fix version.
     */
    private static final int FIX_OFFSET = 12;
    /**
     * The mask for the patch version.
     */
    private static final long PATCH_MASK = 0x00000ff0L;
    /**
     * The offset for the patch version.
     */
    private static final int PATCH_OFFSET = 4;
    /**
     * Number of letters.
     */
    private static final int NUM_LETTERS = 26;
    /**
     * The status mask.
     */
    private static final int STATUS_MASK = 0x0000000f;

    /**
     * Returns the open SSL version as a string.
     *
     * @param openSSLVersionConstant The open SSL version
     * @return the version of openssl
     */
    protected static String getOpenSSLVersion(long openSSLVersionConstant) {
        final long major = openSSLVersionConstant >>> MAJOR_OFFSET;
        final long minor = (openSSLVersionConstant & MINOR_MASK) >>> MINOR_OFFSET;
        final long fix = (openSSLVersionConstant & FIX_MASK) >>> FIX_OFFSET;
        final long patchLevel = (openSSLVersionConstant & PATCH_MASK) >>> PATCH_OFFSET;
        final String patch = 0 == patchLevel || patchLevel > NUM_LETTERS ? "" : String.valueOf((char) (patchLevel + 'a' - 1));
        final int statusCode = (int) (openSSLVersionConstant & STATUS_MASK);
        final String status = 0xf == statusCode ? "" : (0 == statusCode ? "-dev" : "-beta" + statusCode);
        return String.format("%d.%d.%d%s%s", major, minor, fix, patch, status);
    }

    /**
     * Returns the name of the Python Package Analyzer.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return "OpenSSL Source Analyzer";
    }

    /**
     * Tell that we are used for information collection.
     *
     * @return INFORMATION_COLLECTION
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }

    /**
     * Returns the set of supported file extensions.
     *
     * @return the set of supported file extensions
     */
    @Override
    protected FileFilter getFileFilter() {
        return OPENSSLV_FILTER;
    }

    /**
     * Returns the setting for the analyzer enabled setting key.
     *
     * @return the setting for the analyzer enabled setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_OPENSSL_ENABLED;
    }

    /**
     * No-op initializer implementation.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException never thrown
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        // Nothing to do here.
    }

    /**
     * Analyzes python packages and adds evidence to the dependency.
     *
     * @param dependency the dependency being analyzed
     * @param engine the engine being used to perform the scan
     * @throws AnalysisException thrown if there is an unrecoverable error
     * analyzing the dependency
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine)
            throws AnalysisException {
        final File file = dependency.getActualFile();
        final String parentName = file.getParentFile().getName();
        final String contents = getFileContents(file);
        String version = null;
        if (!contents.isEmpty()) {
            final Matcher strMatcher = VERSION_STR_PATTERN.matcher(contents);
            if (strMatcher.find()) {
                version = strMatcher.group(1);
            } else {
                final Matcher matcher = VERSION_PATTERN.matcher(contents);
                if (matcher.find()) {
                    version = getOpenSSLVersion(Long.parseLong(matcher.group(1), HEXADECIMAL));
                }
            }
        }
        if (version != null) {
            dependency.addEvidence(EvidenceType.VERSION, OPENSSLV_H, "Version Constant",
                    version, Confidence.HIGH);
            try {
                final PackageURL purl = PackageURLBuilder.aPackageURL().withType("generic")
                        .withName("openssl").withVersion(version).build();
                dependency.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
            } catch (MalformedPackageURLException ex) {
                LOGGER.debug("Unable to build package url for openssl", ex);
                final GenericIdentifier id = new GenericIdentifier("generic:openssl@" + version, Confidence.HIGHEST);
                dependency.addSoftwareIdentifier(id);
            }
            dependency.setDisplayFileName(parentName + File.separatorChar + OPENSSLV_H);
            dependency.addEvidence(EvidenceType.VENDOR, OPENSSLV_H, "Vendor", "OpenSSL", Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.PRODUCT, OPENSSLV_H, "Product", "OpenSSL", Confidence.HIGHEST);
        } else {
            engine.removeDependency(dependency);
        }
    }

    /**
     * Retrieves the contents of a given file.
     *
     * @param actualFile the file to read
     * @return the contents of the file
     * @throws AnalysisException thrown if there is an IO Exception
     */
    private String getFileContents(final File actualFile)
            throws AnalysisException {
        try {
            return new String(Files.readAllBytes(actualFile.toPath()), StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file.", e);
        }
    }
}
