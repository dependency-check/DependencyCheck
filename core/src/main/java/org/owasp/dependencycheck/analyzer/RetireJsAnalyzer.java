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
 * Copyright (c) 2017 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.esotericsoftware.minlog.Log;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import com.h3xstream.retirejs.repo.JsLibrary;
import com.h3xstream.retirejs.repo.JsLibraryResult;
import com.h3xstream.retirejs.repo.JsVulnerability;
import com.h3xstream.retirejs.repo.ScannerFacade;
import com.h3xstream.retirejs.repo.VulnerabilitiesRepository;
import com.h3xstream.retirejs.repo.VulnerabilitiesRepositoryLoader;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.UrlValidator;
import org.json.JSONException;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.update.RetireJSDataSource;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.Reference;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.exception.WriteLockException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.WriteLock;
import org.owasp.dependencycheck.utils.search.FileContentSearch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.IOUtils;

/**
 * The RetireJS analyzer uses the manually curated list of vulnerabilities from
 * the RetireJS community along with the necessary information to assist in
 * identifying vulnerable components. Vulnerabilities documented by the RetireJS
 * community usually originate from other sources such as the NVD, OSVDB, NSP,
 * and various issue trackers.
 *
 * @author Steve Springett
 */
@ThreadSafe
public class RetireJsAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.JAVASCRIPT;
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(RetireJsAnalyzer.class);
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "RetireJS Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.FINDING_ANALYSIS;
    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final String[] EXTENSIONS = {"js"};
    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(EXTENSIONS).build();
    /**
     * An instance of the local VulnerabilitiesRepository
     */
    private VulnerabilitiesRepository jsRepository;
    /**
     * The list of filters used to exclude files by file content; the intent is
     * that this could be used to filter out a companies custom files by filter
     * on their own copyright statements.
     */
    private String[] filters = null;

    /**
     * Flag indicating whether non-vulnerable JS should be excluded if they are
     * contained in a JAR.
     */
    //TODO implement this
    @SuppressWarnings("FieldMayBeFinal")
    private boolean skipNonVulnerableInJAR = true;

    /**
     * Returns the FileFilter.
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * Determines if the file can be analyzed by the analyzer.
     *
     * @param pathname the path to the file
     * @return true if the file can be analyzed by the given analyzer; otherwise
     * false
     */
    @Override
    public boolean accept(File pathname) {
        try {
            final boolean accepted = super.accept(pathname);
            if (accepted && !pathname.exists()) {
                //file may not yet have been extracted from an archive
                super.setFilesMatched(true);
                return true;
            }
            if (accepted && filters != null && FileContentSearch.contains(pathname, filters)) {
                return false;
            }
            return accepted;
        } catch (IOException ex) {
            LOGGER.warn(String.format("Error testing file %s", pathname), ex);
        }
        return false;
    }

    /**
     * Initializes the analyzer with the configured settings.
     *
     * @param settings the configured settings to use
     */
    @Override
    public void initialize(Settings settings) {
        super.initialize(settings);
        if (this.isEnabled()) {
            this.filters = settings.getArray(Settings.KEYS.ANALYZER_RETIREJS_FILTERS);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException thrown if there is an exception during
     * initialization
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        // RetireJS outputs a bunch of repeated output like the following for
        // vulnerable dependencies, with little context:
        //
        // INFO: Vulnerability found: jquery below 1.6.3
        //
        // This logging is suppressed because it isn't particularly useful, and
        // it aligns with other analyzers that don't log such information.
        Log.set(Log.LEVEL_WARN);

        File repoFile = null;
        boolean repoEmpty = false;
        try {
            final String configuredUrl = getSettings().getString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, RetireJSDataSource.DEFAULT_JS_URL);
            final URL url = new URL(configuredUrl);
            final File filepath = new File(url.getPath());
            repoFile = new File(getSettings().getDataDirectory(), filepath.getName());
            if (!repoFile.isFile() || repoFile.length() <= 1L) {
                LOGGER.warn("Retire JS repository is empty or missing - attempting to force the update");
                repoEmpty = true;
                getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_FORCEUPDATE, true);
            }
        } catch (FileNotFoundException ex) {
            this.setEnabled(false);
            throw new InitializationException(String.format("RetireJS repo does not exist locally (%s)", repoFile), ex);
        } catch (IOException ex) {
            this.setEnabled(false);
            throw new InitializationException("Failed to initialize the RetireJS", ex);
        }

        final boolean autoupdate = getSettings().getBoolean(Settings.KEYS.AUTO_UPDATE, true);
        final boolean forceupdate = getSettings().getBoolean(Settings.KEYS.ANALYZER_RETIREJS_FORCEUPDATE, false);
        if ((!autoupdate && forceupdate) || (autoupdate && repoEmpty)) {
            final RetireJSDataSource ds = new RetireJSDataSource();
            try {
                ds.update(engine);
            } catch (UpdateException ex) {
                throw new InitializationException("Unable to initialize the Retire JS repository", ex);
            }
        }

        //several users are reporting that the retire js repository is getting corrupted.
        try (WriteLock lock = new WriteLock(getSettings(), true, repoFile.getName() + ".lock")) {
            final File temp = getSettings().getTempDirectory();
            final File tempRepo = new File(temp, repoFile.getName());
            LOGGER.debug("copying retireJs repo {} to {}", repoFile.toPath(), tempRepo.toPath());
            Files.copy(repoFile.toPath(), tempRepo.toPath());
            repoFile = tempRepo;
        } catch (WriteLockException | IOException ex) {
            this.setEnabled(false);
            throw new InitializationException("Failed to copy the RetireJS repo", ex);
        }
        try (FileInputStream in = new FileInputStream(repoFile)) {
            this.jsRepository = new VulnerabilitiesRepositoryLoader().loadFromInputStream(in);
        } catch (JSONException ex) {
            this.setEnabled(false);
            throw new InitializationException("Failed to initialize the RetireJS repo: `" + repoFile
                    + "` appears to be malformed. Please delete the file or run the dependency-check purge "
                    + "command and re-try running dependency-check.", ex);
        } catch (IOException ex) {
            this.setEnabled(false);
            throw new InitializationException("Failed to initialize the RetireJS repo", ex);
        }
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
        return Settings.KEYS.ANALYZER_RETIREJS_ENABLED;
    }

    /**
     * Analyzes the specified JavaScript file.
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the file
     * file.
     */
    @Override
    public void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (dependency.isVirtual()) {
            return;
        }
        try (InputStream fis = new FileInputStream(dependency.getActualFile())) {
            final byte[] fileContent = IOUtils.toByteArray(fis);
            final ScannerFacade scanner = new ScannerFacade(jsRepository);
            final List<JsLibraryResult> results;
            try {
                results = scanner.scanScript(dependency.getActualFile().getAbsolutePath(), fileContent, 0);
            } catch (StackOverflowError ex) {
                final String msg = String.format("An error occured trying to analyze %s. "
                        + "To resolve this error please try increasing the Java stack size to "
                        + "8mb and re-run dependency-check:%n%n"
                        + "(win) : set JAVA_OPTS=\"-Xss8192k\"%n"
                        + "(*nix): export JAVA_OPTS=\"-Xss8192k\"%n%n",
                        dependency.getDisplayFileName());
                throw new AnalysisException(msg, ex);
            }
            if (results.size() > 0) {
                for (JsLibraryResult libraryResult : results) {

                    final JsLibrary lib = libraryResult.getLibrary();
                    dependency.setName(lib.getName());
                    dependency.setVersion(libraryResult.getDetectedVersion());
                    try {
                        final PackageURL purl = PackageURLBuilder.aPackageURL().withType("javascript")
                                .withName(lib.getName()).withVersion(libraryResult.getDetectedVersion()).build();
                        dependency.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
                    } catch (MalformedPackageURLException ex) {
                        LOGGER.debug("Unable to build package url for retireJS", ex);
                        final GenericIdentifier id = new GenericIdentifier("javascript:" + lib.getName() + "@"
                                + libraryResult.getDetectedVersion(), Confidence.HIGHEST);
                        dependency.addSoftwareIdentifier(id);
                    }

                    dependency.addEvidence(EvidenceType.VERSION, "RetireJS", "version", libraryResult.getDetectedVersion(), Confidence.HIGH);
                    dependency.addEvidence(EvidenceType.PRODUCT, "RetireJS", "name", libraryResult.getLibrary().getName(), Confidence.HIGH);
                    dependency.addEvidence(EvidenceType.VENDOR, "RetireJS", "name", libraryResult.getLibrary().getName(), Confidence.HIGH);

                    final List<Vulnerability> vulns = new ArrayList<>();
                    final JsVulnerability jsVuln = libraryResult.getVuln();

                    if (jsVuln.getIdentifiers().containsKey("CVE") || jsVuln.getIdentifiers().containsKey("osvdb")) {
                        /* CVEs and OSVDB are an array of Strings - each one a unique vulnerability.
                         * So the JsVulnerability we are operating on may actually be representing
                         * multiple vulnerabilities. */

                        //TODO - can we refactor this to avoid russian doll syndrome (i.e. nesting)?
                        //CSOFF: NestedForDepth
                        for (Map.Entry<String, List<String>> entry : jsVuln.getIdentifiers().entrySet()) {
                            final String key = entry.getKey();
                            final List<String> value = entry.getValue();
                            if ("CVE".equals(key)) {
                                for (String cve : value) {
                                    Vulnerability vuln = engine.getDatabase().getVulnerability(StringUtils.trim(cve));
                                    if (vuln == null) {
                                        /* The CVE does not exist in the database and is likely in a
                                         * reserved state. Create a new one without adding it to the
                                         * database and populate it as best as possible. */
                                        vuln = new Vulnerability();
                                        vuln.setName(cve);
                                        vuln.setUnscoredSeverity(jsVuln.getSeverity());
                                        vuln.setSource(Vulnerability.Source.RETIREJS);
                                    }
                                    jsVuln.getInfo().stream().map((info) -> {
                                        if (UrlValidator.getInstance().isValid(info)) {
                                            return new Reference(info, "info", info);
                                        }
                                        return new Reference(info, "info", null);
                                    }).forEach(vuln::addReference);
                                    vulns.add(vuln);
                                }
                            } else if ("osvdb".equals(key)) {
                                //todo - convert to map/collect
                                value.forEach((osvdb) -> {
                                    final Vulnerability vuln = new Vulnerability();
                                    vuln.setName(osvdb);
                                    vuln.setSource(Vulnerability.Source.RETIREJS);
                                    vuln.setUnscoredSeverity(jsVuln.getSeverity());
                                    jsVuln.getInfo().stream().map((info) -> {
                                        if (UrlValidator.getInstance().isValid(info)) {
                                            return new Reference(info, "info", info);
                                        }
                                        return new Reference(info, "info", null);
                                    }).forEach(vuln::addReference);
                                    vulns.add(vuln);
                                });
                            }
                            dependency.addVulnerabilities(vulns);
                        }
                        //CSON: NestedForDepth
                    } else {
                        final Vulnerability individualVuln = new Vulnerability();
                        /* ISSUE, BUG, etc are all individual vulnerabilities. The result of this
                         * iteration will be one vulnerability. */
                        for (Map.Entry<String, List<String>> entry : jsVuln.getIdentifiers().entrySet()) {
                            final String key = entry.getKey();
                            final List<String> value = entry.getValue();
                            // CSOFF: NeedBraces
                            if (null != key) {
                                switch (key) {
                                    case "summary":
                                        if (null == individualVuln.getName()) {
                                            individualVuln.setName(value.get(0));
                                        }
                                        individualVuln.setDescription(value.get(0));
                                        break;
                                    case "issue":
                                        individualVuln.setName(libraryResult.getLibrary().getName() + " issue: " + value.get(0));
                                        if (UrlValidator.getInstance().isValid(value.get(0))) {
                                            individualVuln.addReference(key, key, value.get(0));
                                        } else {
                                            individualVuln.addReference(key, value.get(0), null);
                                        }
                                        break;
                                    case "bug":
                                        individualVuln.setName(libraryResult.getLibrary().getName() + " bug: " + value.get(0));
                                        if (UrlValidator.getInstance().isValid(value.get(0))) {
                                            individualVuln.addReference(key, key, value.get(0));
                                        } else {
                                            individualVuln.addReference(key, value.get(0), null);
                                        }
                                        break;
                                    case "pr":
                                        individualVuln.setName(libraryResult.getLibrary().getName() + " pr: " + value.get(0));
                                        if (UrlValidator.getInstance().isValid(value.get(0))) {
                                            individualVuln.addReference(key, key, value.get(0));
                                        } else {
                                            individualVuln.addReference(key, value.get(0), null);
                                        }
                                        break;
                                    //case "release":
                                    default:
                                        if (UrlValidator.getInstance().isValid(value.get(0))) {
                                            individualVuln.addReference(key, key, value.get(0));
                                        } else {
                                            individualVuln.addReference(key, value.get(0), null);
                                        }
                                        break;
                                }
                            }
                            // CSON: NeedBraces
                        }
                        if (StringUtils.isBlank(individualVuln.getName())) {
                            individualVuln.setName("Vulnerability in " + libraryResult.getLibrary().getName());
                        }
                        individualVuln.setSource(Vulnerability.Source.RETIREJS);
                        individualVuln.setUnscoredSeverity(jsVuln.getSeverity());
                        jsVuln.getInfo().stream().map((info) -> {
                            if (UrlValidator.getInstance().isValid(info)) {
                                return new Reference(info, "info", info);
                            }
                            return new Reference(info, "info", null);
                        }).forEach(individualVuln::addReference);

                        dependency.addVulnerability(individualVuln);
                    }
                }
            } else if (getSettings().getBoolean(Settings.KEYS.ANALYZER_RETIREJS_FILTER_NON_VULNERABLE, false)) {
                engine.removeDependency(dependency);
            }
        } catch (IOException | DatabaseException e) {
            throw new AnalysisException(e);
        }
    }

    @Override
    protected void closeAnalyzer() throws Exception {
        Log.set(Log.LEVEL_INFO);
    }
}
