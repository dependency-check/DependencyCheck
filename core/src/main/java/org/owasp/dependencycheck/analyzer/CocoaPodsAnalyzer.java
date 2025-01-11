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
 * Copyright (c) 2016 IBM Corporation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Checksum;
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
 * This analyzer is used to analyze SWIFT and Objective-C packages by collecting
 * information from .podspec files. CocoaPods dependency manager see
 * https://cocoapods.org/.
 *
 * @author Bianca Jiang (https://twitter.com/biancajiang)
 */
@Experimental
@ThreadSafe
public class CocoaPodsAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.IOS;

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CocoaPodsAnalyzer.class);
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "CocoaPods Package Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The file name to scan.
     */
    public static final String PODSPEC = "podspec";
    /**
     * The file name to scan.
     */
    public static final String PODFILE_LOCK = "Podfile.lock";
    /**
     * Filter that detects files named "*.podspec" and "Podfile.lock".
     */
    private static final FileFilter PODS_FILTER = FileFilterBuilder.newInstance().addExtensions(PODSPEC).addFilenames(PODFILE_LOCK).build();

    /**
     * The capture group #1 is the block variable. e.g. "Pod::Spec.new do
     * |spec|"
     */
    private static final Pattern PODSPEC_BLOCK_PATTERN = Pattern.compile("Pod::Spec\\.new\\s+?do\\s+?\\|(.+?)\\|");

    /**
     * The capture group #1 is the dependency name, #2 is dependency version
     */
    private static final Pattern PODFILE_LOCK_DEPENDENCY_PATTERN = Pattern.compile("  - \"?(.*) \\((\\d+(\\.\\d+){0,4})\\)\"?");

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return PODS_FILTER;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) {
        // NO-OP
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
        return Settings.KEYS.ANALYZER_COCOAPODS_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine)
            throws AnalysisException {
        if (PODFILE_LOCK.equals(dependency.getFileName())) {
            analyzePodfileLockDependencies(dependency, engine);
        }

        if (dependency.getFileName().endsWith(PODSPEC)) {
            analyzePodspecDependency(dependency);
        }
    }

    /**
     * Analyzes the podfile.lock file to extract evidence for the dependency.
     *
     * @param podfileLock the dependency to analyze
     * @param engine the analysis engine
     * @throws AnalysisException thrown if there is an error analyzing the
     * dependency
     */
    private void analyzePodfileLockDependencies(Dependency podfileLock, Engine engine)
            throws AnalysisException {
        engine.removeDependency(podfileLock);

        final String contents;
        try {
            contents = new String(Files.readAllBytes(podfileLock.getActualFile().toPath()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file.", e);
        }

        final Matcher matcher = PODFILE_LOCK_DEPENDENCY_PATTERN.matcher(contents);
        while (matcher.find()) {
            final String name = matcher.group(1);
            final String version = matcher.group(2);

            final Dependency dependency = new Dependency(podfileLock.getActualFile(), true);
            dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
            dependency.setName(name);
            dependency.setVersion(version);

            try {
                final PackageURLBuilder builder = PackageURLBuilder.aPackageURL().withType("cocoapods").withName(dependency.getName());
                if (dependency.getVersion() != null) {
                    builder.withVersion(dependency.getVersion());
                }
                final PackageURL purl = builder.build();
                dependency.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
            } catch (MalformedPackageURLException ex) {
                LOGGER.debug("Unable to build package url for cocoapods", ex);
                final GenericIdentifier id;
                if (dependency.getVersion() != null) {
                    id = new GenericIdentifier("cocoapods:" + dependency.getName() + "@" + dependency.getVersion(), Confidence.HIGHEST);
                } else {
                    id = new GenericIdentifier("cocoapods:" + dependency.getName(), Confidence.HIGHEST);
                }
                dependency.addSoftwareIdentifier(id);
            }

            final String packagePath = String.format("%s:%s", name, version);
            dependency.setPackagePath(packagePath);
            dependency.setDisplayFileName(packagePath);
            dependency.setSha1sum(Checksum.getSHA1Checksum(packagePath));
            dependency.setSha256sum(Checksum.getSHA256Checksum(packagePath));
            dependency.setMd5sum(Checksum.getMD5Checksum(packagePath));
            dependency.addEvidence(EvidenceType.VENDOR, PODFILE_LOCK, "name", name, Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.PRODUCT, PODFILE_LOCK, "name", name, Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.VERSION, PODFILE_LOCK, "version", version, Confidence.HIGHEST);
            engine.addDependency(dependency);
        }
    }

    /**
     * Analyzes the podspec and adds the evidence to the dependency.
     *
     * @param dependency the dependency
     * @throws AnalysisException thrown if there is an error analyzing the
     * podspec
     */
    private void analyzePodspecDependency(Dependency dependency)
            throws AnalysisException {
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
        String contents;
        try {
            contents = new String(Files.readAllBytes(dependency.getActualFile().toPath()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file.", e);
        }
        final Matcher matcher = PODSPEC_BLOCK_PATTERN.matcher(contents);
        if (matcher.find()) {
            contents = contents.substring(matcher.end());
            final String blockVariable = matcher.group(1);
            PackageURLBuilder builder = null;
            final String name = determineEvidence(contents, blockVariable, "name");
            if (!name.isEmpty()) {
                dependency.addEvidence(EvidenceType.PRODUCT, PODSPEC, "name_project", name, Confidence.HIGHEST);
                dependency.addEvidence(EvidenceType.VENDOR, PODSPEC, "name_project", name, Confidence.HIGHEST);
                dependency.setName(name);

                builder = PackageURLBuilder.aPackageURL();
                builder.withType("cocoapods").withName(name);
            }
            final String version = determineEvidence(contents, blockVariable, "version");
            if (!version.isEmpty()) {
                dependency.addEvidence(EvidenceType.VERSION, PODSPEC, "version", version, Confidence.HIGHEST);
                dependency.setVersion(version);
                if (builder != null) {
                    builder.withVersion(version);
                }
            }

            final String summary = determineEvidence(contents, blockVariable, "summary");
            if (!summary.isEmpty()) {
                dependency.addEvidence(EvidenceType.PRODUCT, PODSPEC, "summary", summary, Confidence.HIGHEST);
                dependency.addEvidence(EvidenceType.VENDOR, PODSPEC, "summary", summary, Confidence.MEDIUM);
            }

            final String author = determineEvidence(contents, blockVariable, "authors?");
            if (!author.isEmpty()) {
                dependency.addEvidence(EvidenceType.VENDOR, PODSPEC, "author", author, Confidence.HIGHEST);
            }
            final String homepage = determineEvidence(contents, blockVariable, "homepage");
            if (!homepage.isEmpty()) {
                dependency.addEvidence(EvidenceType.VENDOR, PODSPEC, "homepage", homepage, Confidence.HIGHEST);
                dependency.addEvidence(EvidenceType.PRODUCT, PODSPEC, "homepage", homepage, Confidence.LOW);
            }
            final String license = determineEvidence(contents, blockVariable, "licen[cs]es?");
            if (!license.isEmpty()) {
                dependency.setLicense(license);
            }

            if (builder != null) {
                try {
                    final PurlIdentifier purl = new PurlIdentifier(builder.build(), homepage, Confidence.HIGHEST);
                    dependency.addSoftwareIdentifier(purl);
                } catch (MalformedPackageURLException ex) {
                    LOGGER.debug("Unable to generate purl for cocoapod", ex);
                    final StringBuilder sb = new StringBuilder("pkg:cocoapods/");
                    sb.append(name);
                    if (!version.isEmpty()) {
                        sb.append("@").append(version);
                    }
                    final GenericIdentifier id = new GenericIdentifier(sb.toString(), Confidence.HIGHEST);
                    dependency.addSoftwareIdentifier(id);
                }
            }
        }
        if (dependency.getVersion() != null && !dependency.getVersion().isEmpty()) {
            dependency.setDisplayFileName(String.format("%s:%s", dependency.getName(), dependency.getVersion()));
        } else {
            dependency.setDisplayFileName(dependency.getName());
        }
        setPackagePath(dependency);
    }

    /**
     * Extracts evidence from the contents and adds it to the given evidence
     * collection.
     *
     * @param contents the text to extract evidence from
     * @param blockVariable the block variable within the content to search for
     * @param fieldPattern the field pattern within the contents to search for
     * @return the evidence
     */
    private String determineEvidence(String contents, String blockVariable, String fieldPattern) {
        String value = "";

        //capture array value between [ ]
        final Matcher arrayMatcher = Pattern.compile(
                String.format("\\s*?%s\\.%s\\s*?=\\s*?\\{\\s*?(.*?)\\s*?\\}", blockVariable, fieldPattern),
                Pattern.CASE_INSENSITIVE).matcher(contents);
        if (arrayMatcher.find()) {
            value = arrayMatcher.group(1);
        } else { //capture single value between quotes
            final Matcher matcher = Pattern.compile(
                    String.format("\\s*?%s\\.%s\\s*?=\\s*?(['\"])(.*?)\\1", blockVariable, fieldPattern),
                    Pattern.CASE_INSENSITIVE).matcher(contents);
            if (matcher.find()) {
                value = matcher.group(2);
            }
        }
        return value;
    }

    /**
     * Sets the package path on the given dependency.
     *
     * @param dep the dependency to update
     */
    private void setPackagePath(Dependency dep) {
        final File file = new File(dep.getFilePath());
        final String parent = file.getParent();
        if (parent != null) {
            dep.setPackagePath(parent);
        }
    }
}
