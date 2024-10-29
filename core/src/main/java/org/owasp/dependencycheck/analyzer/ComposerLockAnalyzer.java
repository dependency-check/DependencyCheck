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
 * Copyright (c) 2015 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.composer.ComposerException;
import org.owasp.dependencycheck.data.composer.ComposerLockParser;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.IOException;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;

/**
 * Used to analyze a composer.lock file for a composer PHP app.
 *
 * @author colezlaw
 */
@Experimental
public class ComposerLockAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.PHP;

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ComposerLockAnalyzer.class);

    /**
     * The analyzer name.
     */
    private static final String ANALYZER_NAME = "Composer.lock analyzer";

    /**
     * composer.json.
     */
    private static final String COMPOSER_LOCK = "composer.lock";

    /**
     * The FileFilter.
     */
    private static final FileFilter FILE_FILTER = FileFilterBuilder.newInstance().addFilenames(COMPOSER_LOCK).build();

    /**
     * Returns the FileFilter.
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILE_FILTER;
    }

    /**
     * Initializes the analyzer.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException thrown if an exception occurs getting an
     * instance of SHA1
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        // do nothing
    }

    /**
     * Entry point for the analyzer.
     *
     * @param dependency the dependency to analyze
     * @param engine the engine scanning
     * @throws AnalysisException if there's a failure during analysis
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        engine.removeDependency(dependency);
        try (FileInputStream fis = new FileInputStream(dependency.getActualFile())) {
            final boolean skipdev = getSettings().getBoolean(Settings.KEYS.ANALYZER_COMPOSER_LOCK_SKIP_DEV, false);
            final ComposerLockParser clp = new ComposerLockParser(fis, skipdev);
            LOGGER.debug("Checking composer.lock file {}", dependency.getActualFilePath());
            clp.process();
            clp.getDependencies().stream().map((dep) -> {
                final Dependency d = new Dependency(dependency.getActualFile(), true);
                final String filePath = String.format("%s:%s/%s/%s", dependency.getFilePath(), dep.getGroup(), dep.getProject(), dep.getVersion());
                d.setName(dep.getProject());
                d.setVersion(dep.getVersion());
                try {
                    final PackageURL purl = PackageURLBuilder.aPackageURL().withType("composer").withNamespace(dep.getGroup())
                            .withName(dep.getProject()).withVersion(dep.getVersion()).build();
                    d.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
                } catch (MalformedPackageURLException ex) {
                    LOGGER.debug("Unable to build package url for composer", ex);
                    d.addSoftwareIdentifier(new GenericIdentifier("composer:" + dep.getGroup() + "/" + dep.getProject()
                            + "@" + dep.getVersion(), Confidence.HIGHEST));
                }
                d.setPackagePath(String.format("%s:%s", dep.getProject(), dep.getVersion()));
                d.setEcosystem(DEPENDENCY_ECOSYSTEM);
                d.setFilePath(filePath);
                d.setSha1sum(Checksum.getSHA1Checksum(filePath));
                d.setSha256sum(Checksum.getSHA256Checksum(filePath));
                d.setMd5sum(Checksum.getMD5Checksum(filePath));
                d.addEvidence(EvidenceType.VENDOR, COMPOSER_LOCK, "vendor", dep.getGroup(), Confidence.HIGHEST);
                d.addEvidence(EvidenceType.PRODUCT, COMPOSER_LOCK, "product", dep.getProject(), Confidence.HIGHEST);
                d.addEvidence(EvidenceType.VERSION, COMPOSER_LOCK, "version", dep.getVersion(), Confidence.HIGHEST);
                return d;
            }).forEach((d) -> {
                LOGGER.debug("Adding dependency {}", d.getDisplayFileName());
                engine.addDependency(d);
            });
        } catch (IOException ex) {
            LOGGER.warn("Error opening dependency {}", dependency.getActualFilePath());
        } catch (ComposerException ce) {
            LOGGER.warn("Error parsing composer.json {}", dependency.getActualFilePath(), ce);
        }
    }

    /**
     * Gets the key to determine whether the analyzer is enabled.
     *
     * @return the key specifying whether the analyzer is enabled
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_COMPOSER_LOCK_ENABLED;
    }

    /**
     * Returns the analyzer's name.
     *
     * @return the analyzer's name
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the phase this analyzer should run under.
     *
     * @return the analysis phase
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }
}
