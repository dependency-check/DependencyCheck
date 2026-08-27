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
 * Copyright (c) 2026 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.processing.GovulncheckProcessor;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.processing.ProcessReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.exceptions.CpeValidationException;

/**
 * Go vulnerability analyzer that runs the Go team's
 * <a href="https://go.dev/doc/security/vuln">govulncheck</a> tool against a Go
 * module and reports the vulnerabilities it finds.
 * <p>
 * Unlike the CPE-matching {@link GolangModAnalyzer}, govulncheck consults the
 * curated Go vulnerability database and performs reachability (call-graph)
 * analysis, so it reports only the vulnerabilities that are actually used by the
 * scanned code. This requires the {@code govulncheck} executable (and the Go
 * toolchain) to be installed; the analyzer disables itself when they are
 * missing.</p>
 *
 * @author Srinivas Chippagiri
 */
@Experimental
public class GolangVulncheckAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(GolangVulncheckAnalyzer.class);

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.GOLANG;

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Golang Vulncheck Analyzer";

    /**
     * The phase that this analyzer runs in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.PRE_INFORMATION_COLLECTION;

    /**
     * The file filter for go.mod - govulncheck is run against the module rooted
     * at the go.mod file.
     */
    private static final FileFilter GO_MOD_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(GolangModAnalyzer.GO_MOD)
            .build();

    /**
     * The path to the govulncheck executable, resolved once.
     */
    private String govulncheckPath = null;

    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_GOLANG_VULNCHECK_ENABLED;
    }

    @Override
    protected FileFilter getFileFilter() {
        return GO_MOD_FILTER;
    }

    /**
     * Resolves the path to the govulncheck executable, honoring the configured
     * path when supplied.
     *
     * @return the path to govulncheck
     */
    private String getGovulncheck() {
        synchronized (this) {
            if (govulncheckPath == null) {
                final String path = getSettings().getString(Settings.KEYS.ANALYZER_GOLANG_VULNCHECK_PATH);
                if (path == null) {
                    govulncheckPath = "govulncheck";
                } else {
                    final File exe = new File(path);
                    if (exe.isFile()) {
                        govulncheckPath = exe.getAbsolutePath();
                    } else {
                        LOGGER.warn("Provided path to `govulncheck` is invalid. Trying the default location. "
                                + "If you do want to set it, please set the `{}` property",
                                Settings.KEYS.ANALYZER_GOLANG_VULNCHECK_PATH);
                        govulncheckPath = "govulncheck";
                    }
                }
            }
            return govulncheckPath;
        }
    }

    /**
     * Launches govulncheck with the given arguments in the given folder.
     *
     * @param folder the working directory
     * @param arguments the arguments to pass to govulncheck
     * @return a handle to the launched process
     * @throws AnalysisException thrown if the process cannot be started
     */
    private Process launchGovulncheck(File folder, List<String> arguments) throws AnalysisException {
        if (!folder.isDirectory()) {
            throw new AnalysisException(String.format("%s should have been a directory.", folder.getAbsolutePath()));
        }
        final List<String> args = new ArrayList<>();
        args.add(getGovulncheck());
        args.addAll(arguments);
        final ProcessBuilder builder = new ProcessBuilder(args);
        builder.directory(folder);
        try {
            LOGGER.debug("Launching: {} from {}", args, folder);
            return builder.start();
        } catch (IOException ioe) {
            throw new AnalysisException("govulncheck initialization failure; this error can be ignored if you are not "
                    + "analyzing Go. Otherwise ensure that govulncheck is installed and the path to govulncheck is "
                    + "correctly specified", ioe);
        }
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        setEnabled(false);
        final Process process;
        try {
            process = launchGovulncheck(getSettings().getTempDirectory(), Collections.singletonList("-version"));
        } catch (AnalysisException ae) {
            final String msg = String.format("Exception from govulncheck process: %s. Disabling %s", ae.getCause(), ANALYZER_NAME);
            throw new InitializationException(msg, ae);
        } catch (IOException ex) {
            throw new InitializationException("Unable to create temporary file, the Golang Vulncheck Analyzer will be disabled", ex);
        }

        try (ProcessReader processReader = new ProcessReader(process)) {
            processReader.readAll();
            final int exitValue = process.exitValue();
            if (exitValue == 0) {
                setEnabled(true);
                LOGGER.debug("{} is enabled.", ANALYZER_NAME);
            } else {
                LOGGER.warn("Unexpected exit code ({}) from `govulncheck -version`. Disabling {}. {}",
                        exitValue, ANALYZER_NAME, StringUtils.trimToEmpty(processReader.getError()));
                throw new InitializationException("Unexpected exit code from govulncheck. Disabling " + ANALYZER_NAME);
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new InitializationException("govulncheck process was interrupted. Disabling " + ANALYZER_NAME);
        } catch (IOException ex) {
            throw new InitializationException("IOException reading govulncheck output. Disabling " + ANALYZER_NAME, ex);
        }
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        final File parentFile = dependency.getActualFile().getParentFile();
        final List<String> arguments = new ArrayList<>();
        arguments.add("-json");
        arguments.add("./...");

        final Process process = launchGovulncheck(parentFile, arguments);
        String error = null;
        try (GovulncheckProcessor processor = new GovulncheckProcessor(dependency, engine);
                ProcessReader processReader = new ProcessReader(process, processor)) {
            processReader.readAll();
            error = processReader.getError();
            if (!StringUtils.isBlank(error)) {
                LOGGER.debug("While analyzing `{}` govulncheck produced the following messages:\n{}",
                        dependency.getFilePath(), error);
            }
            final int exitValue = process.exitValue();
            // govulncheck exits 0 in JSON mode even when vulnerabilities are found; a non-zero
            // code generally indicates a run problem (e.g. the module failed to build). The
            // output has already been parsed at this point, so log rather than fail the scan.
            if (exitValue != 0) {
                LOGGER.warn("govulncheck returned exit code {} while analyzing '{}'. Results may be incomplete. {}",
                        exitValue, dependency.getFilePath(), StringUtils.trimToEmpty(error));
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new AnalysisException("govulncheck process interrupted while analyzing '" + dependency.getFilePath() + "'", ie);
        } catch (IOException | CpeValidationException ex) {
            throw new AnalysisException("Error while analyzing '" + dependency.getFilePath() + "' with govulncheck", ex);
        }
    }
}
