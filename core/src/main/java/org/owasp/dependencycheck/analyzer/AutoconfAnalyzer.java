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

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.UrlStringUtils;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Used to analyze Autoconf input files named configure.ac or configure.in.
 * Files simply named "configure" are also analyzed, assuming they are generated
 * by Autoconf, and contain certain special package descriptor variables.
 *
 * @author Dale Visser
 * @see <a href="https://www.gnu.org/software/autoconf/">Autoconf - GNU Project
 * - Free Software Foundation (FSF)</a>
 */
@Experimental
public class AutoconfAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * Autoconf output filename.
     */
    private static final String CONFIGURE = "configure";

    /**
     * Autoconf input filename.
     */
    private static final String CONFIGURE_IN = "configure.in";

    /**
     * Autoconf input filename.
     */
    private static final String CONFIGURE_AC = "configure.ac";

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Autoconf Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final String[] EXTENSIONS = {"ac", "in"};

    /**
     * Matches AC_INIT variables in the output configure script.
     */
    private static final Pattern PACKAGE_VAR = Pattern.compile(
            "PACKAGE_(.+?)='(.*?)'", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

    /**
     * Matches AC_INIT statement in configure.ac file.
     */
    private static final Pattern AC_INIT_PATTERN;

    static {
        // each instance of param or sep_param has a capture group
        final String param = "\\[{0,2}(.+?)\\]{0,2}";
        final String sepParam = "\\s*,\\s*" + param;
        // Group 1: Package
        // Group 2: Version
        // Group 3: optional
        // Group 4: Bug report address (if it exists)
        // Group 5: optional
        // Group 6: Tarname (if it exists)
        // Group 7: optional
        // Group 8: URL (if it exists)
        AC_INIT_PATTERN = Pattern.compile(String.format(
                "AC_INIT\\(%s%s(%s)?(%s)?(%s)?\\s*\\)", param, sepParam,
                sepParam, sepParam, sepParam), Pattern.DOTALL
                | Pattern.CASE_INSENSITIVE);
    }

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFilenames(CONFIGURE).addExtensions(
            EXTENSIONS).build();

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
        return Settings.KEYS.ANALYZER_AUTOCONF_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine)
            throws AnalysisException {
        final File actualFile = dependency.getActualFile();
        final String name = actualFile.getName();
        if (name.startsWith(CONFIGURE)) {
            final File parent = actualFile.getParentFile();
            final String parentName = parent.getName();
            dependency.setDisplayFileName(parentName + "/" + name);
            final boolean isOutputScript = CONFIGURE.equals(name);
            if (isOutputScript || CONFIGURE_AC.equals(name)
                    || CONFIGURE_IN.equals(name)) {
                final String contents = getFileContents(actualFile);
                if (!contents.isEmpty()) {
                    if (isOutputScript) {
                        extractConfigureScriptEvidence(dependency, name, contents);
                    } else {
                        gatherEvidence(dependency, name, contents);
                    }
                }
            }
        } else {
            engine.removeDependency(dependency);
        }
    }

    /**
     * Extracts evidence from the configuration.
     *
     * @param dependency the dependency being analyzed
     * @param name the name of the source of evidence
     * @param contents the contents to analyze for evidence
     */
    private void extractConfigureScriptEvidence(Dependency dependency,
                                                final String name, final String contents) {
        final Matcher matcher = PACKAGE_VAR.matcher(contents);
        while (matcher.find()) {
            final String variable = matcher.group(1);
            final String value = matcher.group(2);
            if (!value.isEmpty()) {
                if (variable.endsWith("NAME")) {
                    dependency.addEvidence(EvidenceType.PRODUCT, name, variable, value, Confidence.HIGHEST);
                    dependency.addEvidence(EvidenceType.VENDOR, name, variable, value, Confidence.MEDIUM);
                } else if ("VERSION".equals(variable)) {
                    dependency.addEvidence(EvidenceType.VERSION, name, variable, value, Confidence.HIGHEST);
                } else if ("BUGREPORT".equals(variable)) {
                    dependency.addEvidence(EvidenceType.VENDOR, name, variable, value, Confidence.HIGH);
                    dependency.addEvidence(EvidenceType.PRODUCT, name, variable, value, Confidence.MEDIUM);
                } else if ("URL".equals(variable)) {
                    dependency.addEvidence(EvidenceType.VENDOR, name, variable, value, Confidence.HIGH);
                    dependency.addEvidence(EvidenceType.PRODUCT, name, variable, value, Confidence.MEDIUM);
                }
            }
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

    /**
     * Gathers evidence from a given file
     *
     * @param dependency the dependency to add evidence to
     * @param name the source of the evidence
     * @param contents the evidence to analyze
     */
    private void gatherEvidence(Dependency dependency, final String name,
                                String contents) {
        final Matcher matcher = AC_INIT_PATTERN.matcher(contents);
        if (matcher.find()) {
            dependency.addEvidence(EvidenceType.PRODUCT, name, "Package", matcher.group(1), Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.VERSION, name, "Package Version", matcher.group(2), Confidence.HIGHEST);

            if (null != matcher.group(3)) {
                dependency.addEvidence(EvidenceType.VENDOR, name, "Bug report address", matcher.group(4), Confidence.HIGH);
            }
            if (null != matcher.group(5)) {
                dependency.addEvidence(EvidenceType.PRODUCT, name, "Tarname", matcher.group(6), Confidence.HIGH);
            }
            if (null != matcher.group(7)) {
                final String url = matcher.group(8);
                if (UrlStringUtils.isUrl(url)) {
                    dependency.addEvidence(EvidenceType.VENDOR, name, "URL", url, Confidence.HIGH);
                }
            }
        }
    }

    /**
     * Initializes the file type analyzer.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException thrown if there is an exception during
     * initialization
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        // No initialization needed.
    }
}
