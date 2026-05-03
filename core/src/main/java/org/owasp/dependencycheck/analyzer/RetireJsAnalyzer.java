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
import com.github.packageurl.PackageURLBuilder;
import com.h3xstream.retirejs.repo.JsLibraryResult;
import com.h3xstream.retirejs.repo.ScannerFacade;
import com.h3xstream.retirejs.repo.VulnerabilitiesRepository;
import com.h3xstream.retirejs.repo.VulnerabilitiesRepositoryLoader;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.UrlValidator;
import org.json.JSONException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
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
import org.owasp.dependencycheck.dependency.naming.Identifier;
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
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.io.IOUtils;

import static org.owasp.dependencycheck.analyzer.RetireJsLibrary.KnownIdentifierTypes.CVE;
import static org.owasp.dependencycheck.analyzer.RetireJsLibrary.KnownIdentifierTypes.GITHUB_SECURITY_ADVISORY;
import static org.owasp.dependencycheck.analyzer.RetireJsLibrary.KnownIdentifierTypes.SECONDARY_NAME_TYPES;
import static org.owasp.dependencycheck.analyzer.RetireJsLibrary.KnownIdentifierTypes.SUMMARY;
import static org.owasp.dependencycheck.analyzer.RetireJsLibrary.KnownIdentifierTypes.singleEntry;
import static org.owasp.dependencycheck.analyzer.RetireJsLibrary.KnownIdentifierTypes.singleItem;

/**
 * The RetireJS analyzer uses the manually curated list of vulnerabilities from
 * the RetireJS community along with the necessary information to assist in
 * identifying vulnerable components. Vulnerabilities documented by the RetireJS
 * community usually originate from other sources such as the NVD, GHSA,
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
            LOGGER.warn("Error testing file {}", pathname, ex);
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
        try (WriteLock ignored = new WriteLock(getSettings(), true, repoFile.getName() + ".lock")) {
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
     * @param engine     the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the file
     */
    @Override
    public void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (dependency.isVirtual()) {
            return;
        }
        try (InputStream fis = new FileInputStream(dependency.getActualFile())) {
            final List<RetireJsLibrary> vulnerableLibraries = new ScannerFacade(jsRepository)
                    .scanScript(dependency.getActualFile().getAbsolutePath(), IOUtils.toByteArray(fis), 0)
                    .stream().map(RetireJsLibrary::adapt).collect(Collectors.toList());

            if (vulnerableLibraries.isEmpty() && getSettings().getBoolean(Settings.KEYS.ANALYZER_RETIREJS_FILTER_NON_VULNERABLE, false)) {
                engine.removeDependency(dependency);
                return;
            }

            for (RetireJsLibrary lib : vulnerableLibraries) {
                dependency.setName(lib.libraryName());
                dependency.setVersion(lib.version());
                dependency.addSoftwareIdentifier(lib.identifier());
                dependency.addEvidence(EvidenceType.VERSION, "RetireJS", "version", lib.version(), Confidence.HIGH);
                dependency.addEvidence(EvidenceType.PRODUCT, "RetireJS", "name", lib.libraryName(), Confidence.HIGH);
                dependency.addEvidence(EvidenceType.VENDOR, "RetireJS", "name", lib.libraryName(), Confidence.HIGH);
                dependency.addVulnerabilities(lib.vulnerabilities(cve -> engine.getDatabase().getVulnerability(cve)));
            }
        } catch (StackOverflowError ex) {
            final String msg = String.format("An error occurred trying to analyze %s. "
                            + "To resolve this error please try increasing the Java stack size to "
                            + "8mb and re-run dependency-check:%n%n"
                            + "(win) : set JAVA_OPTS=\"-Xss8m\"%n"
                            + "(*nix): export JAVA_OPTS=\"-Xss8m\"%n%n",
                    dependency.getDisplayFileName());
            throw new AnalysisException(msg, ex);
        } catch (IOException | DatabaseException e) {
            throw new AnalysisException(e);
        }
    }

    @Override
    protected void closeAnalyzer() throws Exception {
        Log.set(Log.LEVEL_INFO);
    }
}

class RetireJsLibrary {
    private static final Logger LOGGER = LoggerFactory.getLogger(RetireJsLibrary.class);

    private final JsLibraryResult result;

    private RetireJsLibrary(JsLibraryResult result) {
        this.result = result;
    }

    static RetireJsLibrary adapt(JsLibraryResult result) {
        return new RetireJsLibrary(result);
    }

    String libraryName() {
        return result.getLibrary().getName();
    }

    String version() {
        return result.getDetectedVersion();
    }

    Identifier identifier() {
        try {
            return new PurlIdentifier(
                    PackageURLBuilder.aPackageURL()
                            .withType("javascript")
                            .withName(libraryName())
                            .withVersion(version())
                            .build(),
                    Confidence.HIGHEST);
        } catch (MalformedPackageURLException ex) {
            LOGGER.debug("Unable to build package url for retireJS; using generic identifier", ex);
            return new GenericIdentifier(String.format("javascript:%s@%s", libraryName(), version()), Confidence.HIGHEST);
        }
    }

    List<Vulnerability> vulnerabilities(KnownCveProvider knownCveProvider) {
        List<Vulnerability> vulns = new RetireJsVulnerabilityIdentifiers(result.getVuln().getIdentifiers())
                .toVulnerabilities(knownCveProvider, result.getVuln().getSeverity());

        for (Vulnerability vuln : vulns) {
            vuln.addReferences(infoReferences());
        }
        return vulns;
    }

    private @NonNull Set<Reference> infoReferences() {
        return result.getVuln().getInfo().stream()
                .map(info -> new Reference(info, "info", UrlValidator.getInstance().isValid(info) ? info : null))
                .collect(Collectors.toSet());
    }

    @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
    private class RetireJsVulnerabilityIdentifiers {

        public static final int MAX_NAME_LENGTH = 100;

        // Preferred global identifiers
        private final List<String> cveIds;
        private final Optional<String> ghsaId;

        // Fallback identifiers that can be used as vuln names
        private final Map<String, String> secondaryNameIds;
        private final Optional<String> summary;

        RetireJsVulnerabilityIdentifiers(Map<String, List<String>> rawIdentifiers) {
            // CVE identifiers can be a list
            this.cveIds = Optional.ofNullable(rawIdentifiers.get(CVE)).orElse(List.of()).stream()
                    .map(StringUtils::trimToNull)
                    .filter(StringUtils::isNotEmpty)
                    .collect(Collectors.toList());

            // Other identifiers are only supported by the underlying schema as single items, so we get the first
            this.ghsaId = singleItem(rawIdentifiers.get(GITHUB_SECURITY_ADVISORY));
            this.secondaryNameIds = SECONDARY_NAME_TYPES.stream()
                    .flatMap(type -> singleEntry(type, rawIdentifiers.get(type)).stream())
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (a, b) -> a, LinkedHashMap::new));

            // Summary is sometimes present; and can be a fallback vulnerability name as well as description
            this.summary = singleItem(rawIdentifiers.get(SUMMARY));
        }

        List<Vulnerability> toVulnerabilities(KnownCveProvider cveProvider, String severity) {
            // Prefer CVEs; and see if we already know about them from the NVD.
            // RetireJS can map multiple CVEs, so create 'N' vulns
            List<Vulnerability> discoveredVulnerabilities = cveIds.stream()
                    .map(cveId -> cveProvider.optional(cveId).orElseGet(() -> retireJsVulnFor(cveId)))
                    .collect(Collectors.toList());

            // We try and index off CVEs that we can find existing from NVD; else create a single new one
            // with the best canonical name we can determine from identifiers
            if (discoveredVulnerabilities.isEmpty()) {
                discoveredVulnerabilities.add(retireJsVulnFor(vulnerabilityName()));
            }

            // For vulnerabilities not referenced externally; populate description and references from identifiers
            discoveredVulnerabilities.stream()
                    .filter(vuln -> Vulnerability.Source.RETIREJS.equals(vuln.getSource()))
                    .forEach(vuln -> {
                        vuln.setUnscoredSeverity(severity);
                        summary.ifPresent(vuln::setDescription);
                        vuln.addReferences(references());
                    });
            return discoveredVulnerabilities;
        }

        private Vulnerability retireJsVulnFor(String name) {
            final Vulnerability vuln = new Vulnerability(name);
            vuln.setSource(Vulnerability.Source.RETIREJS);
            return vuln;
        }


        private @NonNull String vulnerabilityName() {
            if (!cveIds.isEmpty()) {
                throw new IllegalStateException("vulnerability names for RetireJS vulnerabilities should be taken from the CVE ID");
            }

            // Use the GHSA as a universal identifier if present; otherwise create a vuln name that is library
            // contextual, as we don't know we have a globally unique ID.
            return ghsaId
                    .or(() -> secondaryNameIds.entrySet().stream().findFirst().map(e -> libraryContextualName(e.getKey(), e.getValue())))
                    .or(() -> summary.filter(this::isSmallSingleLine))
                    .orElseGet(() -> "Vulnerability in " + libraryName());
        }

        private String libraryContextualName(String type, String id) {
            return String.format("%s %s: %s", libraryName(), type, id);
        }

        private boolean isSmallSingleLine(String value) {
            return value.length() <= MAX_NAME_LENGTH && value.lines().limit(2).count() == 1;
        }

        private Set<Reference> references() {
            Set<Reference> references = new HashSet<>();
            // RetireJS identifiers are never URLs
            ghsaId.ifPresent(id -> references.add(new Reference(id, "ghsaId", null)));
            secondaryNameIds.forEach((type, id) -> references.add(new Reference(id, type, null)));
            return references;
        }
    }

    @FunctionalInterface
    interface KnownCveProvider {
        @Nullable Vulnerability lookup(String cve);

        default @NonNull Optional<Vulnerability> optional(String cve) {
            return Optional.ofNullable(lookup(cve));
        }
    }

    /**
     * Types of identifiers within the RetireJS repo. Note that there are some legacy/deprecated types which we do not
     * attempt to handle (e.g osvdb, retid, tenable, gist, PR. blog)
     * <br/>
     * Resources:
     *  - <a href="https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json">Latest raw data </a>
     *  - <a href="https://github.com/RetireJS/retire.js/blob/700590ffc92f993dfe15af1b89e364b443bd9bfa/node/src/types.ts#L23-L37">TypeScript types for the identifiers</a>
     *  - <a href="https://github.com/RetireJS/retire.js/blob/700590ffc92f993dfe15af1b89e364b443bd9bfa/node/src/repo.ts#L29-L57">Repo validation</a>
     */
    interface KnownIdentifierTypes {
        String CVE = "CVE";
        String GITHUB_SECURITY_ADVISORY = "githubID";
        List<String> SECONDARY_NAME_TYPES = List.of("issue", "bug", "PR");
        String SUMMARY = "summary";

        static @NonNull Optional<String> singleItem(@Nullable List<String> identifiers) {
            return Optional.ofNullable(identifiers)
                    .flatMap(s -> s.stream().map(StringUtils::trimToNull).filter(Objects::nonNull).findFirst());
        }

        static @NonNull Optional<Map.Entry<String, String>> singleEntry(@NonNull String type, @Nullable List<String> identifiers) {
            return singleItem(identifiers).map(id -> Map.entry(type, id));
        }
    }
}
