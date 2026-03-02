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

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.lang3.StringUtils;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.processing.BundlerAuditProcessor;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.processing.ProcessReader;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.exceptions.CpeValidationException;

/**
 * Used to analyze Ruby Bundler Gemspec.lock files utilizing the 3rd party
 * bundle-audit tool.
 *
 * @author Dale Visser
 */
@ThreadSafe
public class RubyBundleAuditAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(RubyBundleAuditAnalyzer.class);

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.RUBY;

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Ruby Bundle Audit Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.PRE_INFORMATION_COLLECTION;
    /**
     * The filter defining which files will be analyzed.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFilenames("Gemfile.lock").build();
    /**
     * Name.
     */
    public static final String NAME = "Name: ";
    /**
     * Version.
     */
    public static final String VERSION = "Version: ";
    /**
     * Advisory.
     */
    public static final String ADVISORY = "Advisory: ";
    /**
     * CVE.
     */
    public static final String CVE = "CVE: ";
    /**
     * Criticality.
     */
    public static final String CRITICALITY = "Criticality: ";

    /**
     * The DAL.
     */
    private CveDB cvedb = null;

    /**
     * If {@link #analyzeDependency(Dependency, Engine)} is called, then we have
     * successfully initialized, and it will be necessary to disable
     * {@link RubyGemspecAnalyzer}.
     */
    private boolean needToDisableGemspecAnalyzer = true;

    /**
     * @return a filter that accepts files named Gemfile.lock
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
        return Settings.KEYS.ANALYZER_BUNDLE_AUDIT_ENABLED;
    }

    /**
     * Launch bundle-audit.
     *
     * @param folder directory that contains bundle audit
     * @param bundleAuditArgs the arguments to pass to bundle audit
     * @return a handle to the process
     * @throws AnalysisException thrown when there is an issue launching bundle
     * audit
     */
    private Process launchBundleAudit(File folder, List<String> bundleAuditArgs) throws AnalysisException {
        if (!folder.isDirectory()) {
            throw new AnalysisException(String.format("%s should have been a directory.", folder.getAbsolutePath()));
        }
        final List<String> args = new ArrayList<>();
        final String bundleAuditPath = getSettings().getString(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_PATH);
        File bundleAudit = null;
        if (bundleAuditPath != null) {
            bundleAudit = new File(bundleAuditPath);
            if (!bundleAudit.isFile()) {
                LOGGER.warn("Supplied `bundleAudit` path is incorrect: {}", bundleAuditPath);
                bundleAudit = null;
            }
        }
        args.add(bundleAudit != null ? bundleAudit.getAbsolutePath() : "bundle-audit");
        args.addAll(bundleAuditArgs);
        final ProcessBuilder builder = new ProcessBuilder(args);

        final String bundleAuditWorkingDirectoryPath = getSettings().getString(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_WORKING_DIRECTORY);
        File bundleAuditWorkingDirectory = null;
        if (bundleAuditWorkingDirectoryPath != null) {
            bundleAuditWorkingDirectory = new File(bundleAuditWorkingDirectoryPath);
            if (!bundleAuditWorkingDirectory.isDirectory()) {
                LOGGER.warn("Supplied `bundleAuditWorkingDirectory` path is incorrect: {}",
                        bundleAuditWorkingDirectoryPath);
                bundleAuditWorkingDirectory = null;
            }
        }
        final File launchBundleAuditFromDirectory = bundleAuditWorkingDirectory != null ? bundleAuditWorkingDirectory : folder;
        builder.directory(launchBundleAuditFromDirectory);
        try {
            LOGGER.info("Launching: {} from {}", args, launchBundleAuditFromDirectory);
            return builder.start();
        } catch (IOException ioe) {
            throw new AnalysisException("bundle-audit initialization failure; this error "
                    + "can be ignored if you are not analyzing Ruby. Otherwise ensure that "
                    + "bundle-audit is installed and the path to bundle audit is correctly "
                    + "specified", ioe);
        }
    }

    /**
     * Initialize the analyzer.
     *
     * @param engine a reference to the dependency-checkException engine
     * @throws InitializationException if anything goes wrong
     */
    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        if (engine != null) {
            this.cvedb = engine.getDatabase();
        }
        String bundleAuditVersionDetails;
        try {
            final List<String> bundleAuditArgs = Collections.singletonList("version");
            final Process process = launchBundleAudit(getSettings().getTempDirectory(), bundleAuditArgs);
            try (ProcessReader processReader = new ProcessReader(process)) {
                processReader.readAll();
                final String error = processReader.getError();
                if (error != null) {
                    LOGGER.warn("Warnings from bundle-audit {}", error);
                }
                bundleAuditVersionDetails = processReader.getOutput();
                final int exitValue = process.exitValue();
                if (exitValue != 0) {
                    setEnabled(false);
                    final String msg = String.format("bundle-audit execution failed - "
                            + "exit code: %d; error: %s ", exitValue, error);
                    throw new InitializationException(msg);
                }
            }
        } catch (AnalysisException ae) {
            setEnabled(false);
            final String msg = String.format("Exception from bundle-audit process: %s. "
                    + "Disabling %s", ae.getCause(), ANALYZER_NAME);
            throw new InitializationException(msg, ae);
        } catch (IOException ex) {
            setEnabled(false);
            throw new InitializationException("Unable to read bundle-audit output.", ex);
        } catch (InterruptedException ex) {
            setEnabled(false);
            final String msg = String.format("Bundle-audit process was interrupted. "
                    + "Disabling %s", ANALYZER_NAME);
            Thread.currentThread().interrupt();
            throw new InitializationException(msg);
        }
        LOGGER.info("{} is enabled and is using bundle-audit with version details: {}. "
                + "Note: It is necessary to manually run \"bundle-audit update\" "
                + "occasionally to keep its database up to date.", ANALYZER_NAME,
                bundleAuditVersionDetails);
    }

    /**
     * Determines if the analyzer can analyze the given file type.
     *
     * @param dependency the dependency to determine if it can analyze
     * @param engine the dependency-checkException engine
     * @throws AnalysisException thrown if there is an analysis exception.
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (needToDisableGemspecAnalyzer) {
            boolean failed = true;
            final String className = RubyGemspecAnalyzer.class.getName();
            for (FileTypeAnalyzer analyzer : engine.getFileTypeAnalyzers()) {
                if (analyzer instanceof RubyBundlerAnalyzer) {
                    ((RubyBundlerAnalyzer) analyzer).setEnabled(false);
                    LOGGER.info("Disabled {} to avoid noisy duplicate results.",
                            RubyBundlerAnalyzer.class.getName());
                } else if (analyzer instanceof RubyGemspecAnalyzer) {
                    ((RubyGemspecAnalyzer) analyzer).setEnabled(false);
                    LOGGER.info("Disabled {} to avoid noisy duplicate results.", className);
                    failed = false;
                }
            }
            needToDisableGemspecAnalyzer = false;
        }
        final File parentFile = dependency.getActualFile().getParentFile();
        final List<String> bundleAuditArgs = Arrays.asList("check", "--verbose");

        final Process process = launchBundleAudit(parentFile, bundleAuditArgs);
        try (BundlerAuditProcessor processor = new BundlerAuditProcessor(dependency, engine);
                ProcessReader processReader = new ProcessReader(process, processor)) {

            processReader.readAll();
            final String error = processReader.getError();
            if (StringUtils.isNoneBlank(error)) {
                LOGGER.warn("Warnings from bundle-audit {}", error);
            }
            final int exitValue = process.exitValue();
            if (exitValue < 0 || exitValue > 1) {
                final String msg = String.format("Unexpected exit code from bundle-audit "
                        + "process; exit code: %s", exitValue);
                throw new AnalysisException(msg);
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new AnalysisException("bundle-audit process interrupted", ie);
        } catch (IOException | CpeValidationException ioe) {
            LOGGER.warn("bundle-audit failure", ioe);
            throw new AnalysisException("bunder-audit error: " + ioe.getMessage(), ioe);
        }
    }
}
