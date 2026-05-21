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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.FileFilter;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This analyzer attempts to filter out erroneous version numbers collected.
 * Initially, this will focus on JAR files that contain a POM version number
 * that matches the file name - if identified all other version information will
 * be removed.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class VersionFilterAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The Logger for use throughout the class
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(VersionFilterAnalyzer.class);

    //<editor-fold defaultstate="collapsed" desc="Constants">
    /**
     * Evidence source.
     */
    private static final String FILE = "file";
    /**
     * Evidence source.
     */
    private static final String POM = "pom";
    /**
     * Evidence source.
     */
    private static final String NEXUS = "nexus";
    /**
     * Evidence source.
     */
    private static final String CENTRAL = "central";
    /**
     * Evidence source.
     */
    private static final String MANIFEST = "Manifest";
    /**
     * Evidence name.
     */
    private static final String VERSION = "version";
    /**
     * Evidence name.
     */
    private static final String IMPLEMENTATION_VERSION = "Implementation-Version";

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Version Filter Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.POST_INFORMATION_COLLECTION3;
    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions("jar").build();

    //</editor-fold>
    //<editor-fold defaultstate="collapsed" desc="Standard implementation of Analyzer">
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
     * Returns the setting key to determine if the analyzer is enabled.
     *
     * @return the key for the analyzer's enabled property
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_VERSION_FILTER_ENABLED;
    }

    /**
     * Returns the FileFilter used to determine which files this analyzer
     * supports (JAR files only).
     *
     * @return the file filter for JAR files
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * No initialization required for this analyzer.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException thrown if there is an exception during
     * initialization
     */
    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        //nothing to initialize
    }
    //</editor-fold>

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
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {

        final Set<Evidence> remove;
        if (dependency.getVersion() != null) {
            remove = dependency.getEvidence(EvidenceType.VERSION).stream()
                    .filter(e -> !e.isFromHint() && !dependency.getVersion().equals(e.getValue()))
                    .collect(Collectors.toSet());
        } else {
            remove = new HashSet<>();
            String fileVersion = null;
            String pomVersion = null;
            String manifestVersion = null;
            for (Evidence e : dependency.getEvidence(EvidenceType.VERSION)) {
                if (FILE.equals(e.getSource()) && VERSION.equals(e.getName())) {
                    fileVersion = e.getValue();
                } else if ((NEXUS.equals(e.getSource()) || CENTRAL.equals(e.getSource())
                        || POM.equals(e.getSource())) && VERSION.equals(e.getName())) {
                    pomVersion = e.getValue();
                } else if (MANIFEST.equals(e.getSource()) && IMPLEMENTATION_VERSION.equals(e.getName())) {
                    manifestVersion = e.getValue();
                }
            }
            //ensure we have at least two not null
            if (((fileVersion == null ? 0 : 1) + (pomVersion == null ? 0 : 1) + (manifestVersion == null ? 0 : 1)) > 1) {
                final DependencyVersion dvFile = new DependencyVersion(fileVersion);
                final DependencyVersion dvPom = new DependencyVersion(pomVersion);
                final DependencyVersion dvManifest = new DependencyVersion(manifestVersion);
                final boolean fileMatch = Objects.equals(dvFile, dvPom) || Objects.equals(dvFile, dvManifest);
                final boolean manifestMatch = Objects.equals(dvManifest, dvPom) || Objects.equals(dvManifest, dvFile);
                final boolean pomMatch = Objects.equals(dvPom, dvFile) || Objects.equals(dvPom, dvManifest);
                if (fileMatch || manifestMatch || pomMatch) {
                    LOGGER.debug("filtering evidence from {}", dependency.getFileName());

                    for (Evidence e : dependency.getEvidence(EvidenceType.VERSION)) {
                        if (!e.isFromHint()
                                && !(pomMatch && VERSION.equals(e.getName())
                                && (NEXUS.equals(e.getSource()) || CENTRAL.equals(e.getSource()) || POM.equals(e.getSource())))
                                && !(fileMatch && VERSION.equals(e.getName()) && FILE.equals(e.getSource()))
                                && !(manifestMatch && MANIFEST.equals(e.getSource()) && IMPLEMENTATION_VERSION.equals(e.getName()))) {
                            remove.add(e);
                        }
                    }
                }
            }
        }
        remove.forEach((e) -> dependency.removeEvidence(EvidenceType.VERSION, e));

        if (dependency.getVersion() == null) {
            final Set<Evidence> evidence = dependency.getEvidence(EvidenceType.VERSION);
            final DependencyVersion version;
            final Evidence e = evidence.stream().findFirst().orElse(null);
            if (e != null) {
                version = DependencyVersionUtil.parseVersion(e.getValue(), true);
                if (version != null && evidence.stream()
                        .map(ev -> DependencyVersionUtil.parseVersion(ev.getValue(), true))
                        .allMatch(version::equals)) {
                    dependency.setVersion(version.toString());
                }
            }
        }
    }
}
