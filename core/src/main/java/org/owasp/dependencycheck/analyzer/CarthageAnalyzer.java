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
 * Copyright (c) 2023 The OWASP Foundation. All Rights Reserved.
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
 * information from Cartfile files. Carthage dependency manager see
 * https://github.com/Carthage/Carthage.
 *
 * Based on CocoaPodsAnalyzer by Bianca Jiang.
 *
 * @author Alin Radut (https://github.com/alinradut)
 */
@Experimental
@ThreadSafe
public class CarthageAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.IOS;

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CarthageAnalyzer.class);
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Carthage Package Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The file name to scan.
     */
    public static final String CARTFILE_RESOLVED = "Cartfile.resolved";
    /**
     * Filter that detects files named "Cartfile.resolved".
     */
    private static final FileFilter CARTHAGE_FILTER = FileFilterBuilder.newInstance().addFilenames(CARTFILE_RESOLVED).build();

    /**
     * The capture group #1 is the dependency type, #2 is the name, #3 is
     * dependency version. The version can be a commit ref, so we can't assume
     * it's a number
     *
     * Example values: - binary "https://dl.google.com/geosdk/GoogleMaps.json"
     * "7.2.0" - git "https://gitlab.matrix.org/matrix-org/olm.git" "3.2.16" -
     * github "alinradut/SwiftEntryKit"
     * "95f4a08f41ddcf2c02e2b22789038774c8c94df5"" - github
     * "CocoaLumberjack/CocoaLumberjack" "3.8.5" - github "realm/realm-swift"
     * "v10.44.0"
     */
    private static final Pattern CARTFILE_RESOLVED_DEPENDENCY_PATTERN = Pattern.compile("(github|git|binary) \"([^\"]+)\" \"([^\"]+)\"");

    /**
     * The capture group #1 is the actual numerical version.
     */
    private static final Pattern CARTFILE_VERSION_PATTERN = Pattern.compile("^v?(\\d+(\\.\\d+){0,4})$");

    /**
     * Capture group #1 is the dependency name.
     *
     * Example values: - robbiehanson/XMPPFramework -
     * CocoaLumberjack/CocoaLumberjack
     */
    private static final Pattern CARTFILE_RESOLVED_GITHUB_DEPENDENCY = Pattern.compile("[a-zA-Z0-9-_]+/([a-zA-Z0-9\\-_\\.]+)");

    /**
     * Capture group #1 is the dependency name.
     */
    private static final Pattern CARTFILE_RESOLVED_GIT_DEPENDENCY = Pattern.compile(".*?/([a-zA-Z0-9\\-_\\.]+).git");

    /**
     * Capture group #1 is the dependency name.
     *
     * Example values: - https://my.domain.com/release/MyFramework.json -
     * file:///some/Path/MyFramework.json - relative/path/MyFramework.json -
     * /absolute/path/MyFramework.json
     */
    private static final Pattern CARTFILE_RESOLVED_BINARY_DEPENDENCY = Pattern.compile("([a-zA-Z0-9\\-_\\.]+).json");

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return CARTHAGE_FILTER;
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
        return Settings.KEYS.ANALYZER_CARTHAGE_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine)
            throws AnalysisException {
        if (CARTFILE_RESOLVED.equals(dependency.getFileName())) {
            analyzeCartfileResolvedDependency(dependency, engine);
        }
    }

    /**
     * Analyzes the Cartfile.resolved and adds the evidence to the dependency.
     *
     * @param cartfileResolved the dependency
     * @param engine a reference to the dependency-check engine
     * @throws AnalysisException thrown if there is an error analyzing the
     * Cartfile
     */
    private void analyzeCartfileResolvedDependency(Dependency cartfileResolved, Engine engine)
            throws AnalysisException {
        engine.removeDependency(cartfileResolved);

        final String contents;
        try {
            contents = new String(Files.readAllBytes(cartfileResolved.getActualFile().toPath()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file.", e);
        }

        final Matcher matcher = CARTFILE_RESOLVED_DEPENDENCY_PATTERN.matcher(contents);
        while (matcher.find()) {
            final String type = matcher.group(1);
            String name = matcher.group(2);
            String version = matcher.group(3);

            final Matcher versionMatcher = CARTFILE_VERSION_PATTERN.matcher(version);
            if (versionMatcher.find()) {
                version = versionMatcher.group(1);
            } else {
                // this is probably a git commit reference, so we'll default to 0.0.0.
                // this will probably bubble up a ton of CVEs, but serves you right for
                // not using semantic versioning.
                version = "0.0.0";
            }

            if (type.contentEquals("git")) {
                final Matcher nameMatcher = CARTFILE_RESOLVED_GIT_DEPENDENCY.matcher(name);
                if (!nameMatcher.find()) {
                    continue;
                }
                name = nameMatcher.group(1);
            } else if (type.contentEquals("github")) {
                final Matcher nameMatcher = CARTFILE_RESOLVED_GITHUB_DEPENDENCY.matcher(name);
                if (!nameMatcher.find()) {
                    continue;
                }
                name = nameMatcher.group(1);
            } else if (type.contentEquals("binary")) {
                final Matcher nameMatcher = CARTFILE_RESOLVED_BINARY_DEPENDENCY.matcher(name);
                if (!nameMatcher.find()) {
                    continue;
                }
                name = nameMatcher.group(1);
            }

            final Dependency dependency = new Dependency(cartfileResolved.getActualFile(), true);
            dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
            dependency.setName(name);
            dependency.setVersion(version);

            try {
                final PackageURLBuilder builder = PackageURLBuilder.aPackageURL().withType("carthage").withName(dependency.getName());
                if (dependency.getVersion() != null) {
                    builder.withVersion(dependency.getVersion());
                }
                final PackageURL purl = builder.build();
                dependency.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
            } catch (MalformedPackageURLException ex) {
                LOGGER.debug("Unable to build package url for carthage", ex);
                final GenericIdentifier id;
                if (dependency.getVersion() != null) {
                    id = new GenericIdentifier("carthage:" + dependency.getName() + "@" + dependency.getVersion(), Confidence.HIGHEST);
                } else {
                    id = new GenericIdentifier("carthage:" + dependency.getName(), Confidence.HIGHEST);
                }
                dependency.addSoftwareIdentifier(id);
            }

            final String packagePath = String.format("%s:%s", name, version);
            dependency.setPackagePath(packagePath);
            dependency.setDisplayFileName(packagePath);
            dependency.setSha1sum(Checksum.getSHA1Checksum(packagePath));
            dependency.setSha256sum(Checksum.getSHA256Checksum(packagePath));
            dependency.setMd5sum(Checksum.getMD5Checksum(packagePath));
            dependency.addEvidence(EvidenceType.VENDOR, CARTFILE_RESOLVED, "name", name, Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.PRODUCT, CARTFILE_RESOLVED, "name", name, Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.VERSION, CARTFILE_RESOLVED, "version", version, Confidence.HIGHEST);
            engine.addDependency(dependency);
        }
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
