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
 * Copyright (c) 2018 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.apache.commons.jcs3.access.exception.CacheException;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.analyzer.exception.UnexpectedAnalysisException;
import org.owasp.dependencycheck.data.cache.DataCache;
import org.owasp.dependencycheck.data.cache.DataCacheFactory;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.data.nodeaudit.NpmCliAuditParser;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.processing.ProcessReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.exceptions.CpeValidationException;

import javax.annotation.concurrent.ThreadSafe;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import static org.owasp.dependencycheck.utils.FileUtils.existsWithContent;

/**
 * Used to analyze Node Package Manager (npm) package-lock.json and
 * npm-shrinkwrap.json files via the `npm audit` command.
 *
 * @author Steve Springett
 */
@ThreadSafe
public class NodeAuditAnalyzer extends AbstractNpmAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NodeAuditAnalyzer.class);
    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.NODEJS;
    /**
     * The file name to scan.
     */
    public static final String PACKAGE_LOCK_JSON = "package-lock.json";
    /**
     * The file name to scan.
     */
    public static final String SHRINKWRAP_JSON = "npm-shrinkwrap.json";

    /**
     * Filter that detects files named "package-lock.json or
     * npm-shrinkwrap.json".
     */
    private static final FileFilter PACKAGE_JSON_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(PACKAGE_LOCK_JSON, SHRINKWRAP_JSON).build();

    /**
     * The path to the `npm` executable.
     */
    private String npmPath;
    /**
     * Persisted disk cache for `npm audit` results.
     */
    private DataCache<List<Advisory>> cache;

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return PACKAGE_JSON_FILTER;
    }

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    @Override
    public String getName() {
        return "Node Audit Analyzer";
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINDING_ANALYSIS;
    }

    /**
     * Returns the key used in the properties file to determine if the analyzer
     * is enabled.
     *
     * @return the enabled property setting key for the analyzer
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED;
    }

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException if there's an error during initialization
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        super.prepareFileTypeAnalyzer(engine);
        if (!isEnabled()) {
            LOGGER.debug("{} is disabled - skipping npm executable check", getName());
            return;
        }
        try {
            cacheNpmCommandPath();
            checkNpmExecutable();
        } catch (Exception ex) {
            this.setEnabled(false);
            LOGGER.warn("The {} has been disabled after failing to find npm. The npm executable was not "
                    + "found or received a non-zero exit value: {}", getName(), ex.getMessage());
            throw new InitializationException("Unable to determine the npm executable to use.", ex);
        }
        if (getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_USE_CACHE, true)) {
            try {
                final DataCacheFactory factory = new DataCacheFactory(getSettings());
                cache = factory.getNodeAuditCache();
            } catch (CacheException ex) {
                getSettings().setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_USE_CACHE, false);
                LOGGER.debug("Error creating cache, disabling caching", ex);
            }
        }
    }

    /**
     * Attempts to determine and cache the path to `npm`.
     */
    private void cacheNpmCommandPath() {
        String value = getSettings().getString(Settings.KEYS.ANALYZER_NPM_PATH);
        if (value == null || value.isBlank()) {
            value = "npm";
        } else {
            final File fileValue = new File(value);
            if (fileValue.isFile()) {
                value = fileValue.getAbsolutePath();
            } else {
                LOGGER.warn("Provided path to the `npm` executable is invalid; defaulting to `npm`.");
                value = "npm";
            }
        }
        npmPath = value;
    }

    /**
     * Verifies that the npm executable can be run.
     */
    private void checkNpmExecutable() {
        final List<String> args = List.of(npmPath, "--version");
        final ProcessBuilder builder = new ProcessBuilder(args);
        try {
            final Process process = builder.start();
            try (ProcessReader processReader = new ProcessReader(process)) {
                processReader.readAll();
                final int exitValue = process.waitFor();
                if (exitValue != 0) {
                    throw new IllegalStateException(String.format("Unable to run npm, unexpected response "
                            + "(exit value %s, output: %s, error: %s)", exitValue,
                            StringUtils.trimToEmpty(processReader.getOutput()), processReader.getError()));
                }
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Unable to run npm.", ex);
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to run npm.", ex);
        }
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (dependency.getDisplayFileName().equals(dependency.getFileName())) {
            engine.removeDependency(dependency);
        }
        final File packageLock = dependency.getActualFile();
        final File shrinkwrap = new File(packageLock.getParentFile(), SHRINKWRAP_JSON);
        if (PACKAGE_LOCK_JSON.equals(dependency.getFileName()) && shrinkwrap.isFile()) {
            LOGGER.debug("Skipping {} because shrinkwrap lock file exists", dependency.getFilePath());
            return;
        }
        if (!existsWithContent(packageLock) || !shouldProcess(packageLock)) {
            return;
        }
        final boolean skipDevDependencies = getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_SKIPDEV, false);
        final File folder = getDependencyDirectory(packageLock);
        try {
            final List<Advisory> advisories = getAdvisories(packageLock, folder, skipDevDependencies);
            final MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
            collectDependencyVersions(folder, skipDevDependencies, dependency, dependencyMap);
            processResults(advisories, engine, dependency, dependencyMap);
        } catch (JSONException e) {
            throw new AnalysisException(String.format("Failed to parse the output of `npm audit` for %s "
                    + "(NodeAuditAnalyzer).", packageLock.getPath()), e);
        } catch (CpeValidationException ex) {
            throw new UnexpectedAnalysisException(ex);
        }
    }

    /**
     * Obtains the advisories for the given lock file - either from the local
     * disk cache or by invoking `npm audit`.
     *
     * @param packageLock the lock file being analyzed
     * @param folder the directory containing the lock file
     * @param skipDevDependencies whether devDependencies should be skipped
     * @return a list of advisories
     * @throws AnalysisException thrown when there is an error running or
     * parsing the `npm audit` output
     */
    private List<Advisory> getAdvisories(File packageLock, File folder, boolean skipDevDependencies) throws AnalysisException {
        String key = null;
        if (cache != null) {
            try {
                key = Checksum.getSHA256Checksum(packageLock) + (skipDevDependencies ? "_prod" : "_all");
                final List<Advisory> cached = cache.get(key);
                if (cached != null) {
                    LOGGER.debug("Cache hit for node audit: {}", key);
                    return cached;
                }
            } catch (IOException | NoSuchAlgorithmException ex) {
                LOGGER.debug("Error calculating the checksum of the lock file; the audit results will not be cached", ex);
                key = null;
            }
        }
        final JSONObject auditReport = fetchNpmAuditReport(folder, skipDevDependencies);
        final List<Advisory> advisories = new NpmCliAuditParser().parse(auditReport);
        if (cache != null && key != null) {
            cache.put(key, advisories);
        }
        return advisories;
    }

    /**
     * Invokes `npm audit` and returns the parsed JSON report.
     *
     * @param folder the directory containing the lock file to audit
     * @param skipDevDependencies whether devDependencies should be skipped
     * @return the JSON report produced by `npm audit`
     * @throws AnalysisException thrown when there is an error running or
     * parsing the `npm audit` output
     */
    private JSONObject fetchNpmAuditReport(File folder, boolean skipDevDependencies) throws AnalysisException {
        final List<String> args = new ArrayList<>();
        args.add(npmPath);
        args.add("audit");
        if (skipDevDependencies) {
            args.add("--omit=dev");
        }
        //do not require an installed node_modules directory - audit the lock file as-is
        args.add("--package-lock-only");
        //vulnerabilities being found must not result in a non-zero exit value
        args.add("--audit-level=none");
        args.add("--json");
        final ProcessBuilder builder = new ProcessBuilder(args);
        builder.directory(folder);
        LOGGER.debug("Launching: {}", args);

        final String report = startAndReadStdoutToString(builder, "npm_audit");
        LOGGER.debug("npm audit report: {}", report);
        try {
            final JSONObject jsonReport = new JSONObject(report);
            if (jsonReport.has("error")) {
                final JSONObject error = jsonReport.getJSONObject("error");
                throw new AnalysisException(String.format("`npm audit` failed with error code %s: %s",
                        error.optString("code"), error.optString("summary")));
            }
            return jsonReport;
        } catch (JSONException e) {
            throw new AnalysisException("`npm audit` returned an invalid response.", e);
        }
    }

    /**
     * Invokes `npm ls` to obtain the resolved dependency tree from the lock
     * file; populating the given map with each module name and version
     * identified and updating the name and version of the dependency being
     * analyzed with the project details.
     *
     * <p>
     * The advisories returned by `npm audit` do not contain the installed
     * version of the affected modules - only the vulnerable version range. The
     * name/version map is used to resolve the installed version.</p>
     *
     * @param folder the directory containing the lock file
     * @param skipDevDependencies whether devDependencies should be skipped
     * @param dependency a reference to the dependency-object for the lock file
     * @param dependencyMap a collection of module/version pairs that is
     * populated while parsing the dependency tree
     * @throws AnalysisException thrown when there is an error running or
     * parsing the `npm ls` output
     */
    private void collectDependencyVersions(File folder, boolean skipDevDependencies, Dependency dependency,
            MultiValuedMap<String, String> dependencyMap) throws AnalysisException {
        final List<String> args = new ArrayList<>();
        args.add(npmPath);
        args.add("ls");
        args.add("--all");
        if (skipDevDependencies) {
            args.add("--omit=dev");
        }
        args.add("--package-lock-only");
        args.add("--json");
        final ProcessBuilder builder = new ProcessBuilder(args);
        builder.directory(folder);
        LOGGER.debug("Launching: {}", args);

        //`npm ls` may exit with a non-zero value for recoverable problems (e.g.
        // missing optional modules) while still producing the dependency tree
        final String output = startAndReadStdoutToString(builder, "npm_ls");
        try {
            final JSONObject tree = new JSONObject(output);
            if (tree.has("error") && !tree.has("dependencies")) {
                final JSONObject error = tree.getJSONObject("error");
                throw new AnalysisException(String.format("`npm ls` failed with error code %s: %s",
                        error.optString("code"), error.optString("summary")));
            }
            final String projectName = tree.optString("name", "");
            final String projectVersion = tree.optString("version", "");
            if (!projectName.isEmpty()) {
                dependency.setName(projectName);
            }
            if (!projectVersion.isEmpty()) {
                dependency.setVersion(projectVersion);
            }
            collectDependencyVersions(tree, dependencyMap);
        } catch (JSONException e) {
            throw new AnalysisException("`npm ls` returned an invalid response.", e);
        }
    }

    /**
     * Recursively walks the dependency tree produced by `npm ls`, adding each
     * module name and version to the given map.
     *
     * @param node a node within the dependency tree
     * @param dependencyMap the collection of module/version pairs being built
     */
    private void collectDependencyVersions(JSONObject node, MultiValuedMap<String, String> dependencyMap) {
        final JSONObject dependencies = node.optJSONObject("dependencies");
        if (dependencies == null) {
            return;
        }
        for (final String name : dependencies.keySet()) {
            final JSONObject child = dependencies.optJSONObject(name);
            if (child != null) {
                final String version = child.optString("version", null);
                if (version != null && !version.isEmpty()) {
                    dependencyMap.put(name, version);
                }
                collectDependencyVersions(child, dependencyMap);
            }
        }
    }

    /**
     * Workaround 64k limitation of InputStream; redirect stdout to a file that
     * we will read later instead of reading directly stdout from the Process's
     * InputStream which is capped at 64k.
     *
     * @param builder a reference to the process builder
     * @param tmpFilePrefix the prefix for the temporary file the output is
     * redirected to
     * @return returns the standard out from the process
     * @throws AnalysisException thrown when the process cannot be started or
     * its output read
     */
    private String startAndReadStdoutToString(ProcessBuilder builder, String tmpFilePrefix) throws AnalysisException {
        try {
            final File tmpFile = getSettings().getTempFile(tmpFilePrefix, "json");
            builder.redirectOutput(tmpFile);
            final Process process = builder.start();
            try (ProcessReader processReader = new ProcessReader(process)) {
                processReader.readAll();
                final String errOutput = processReader.getError();
                if (!StringUtils.isBlank(errOutput)) {
                    LOGGER.debug("Process Error Out: {}", errOutput);
                }
                return Files.readString(tmpFile.toPath());
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new AnalysisException("npm process was interrupted.", ex);
            }
        } catch (IOException ioe) {
            throw new AnalysisException("npm audit failure; this error can be ignored if you are not analyzing "
                    + "projects with an npm lockfile.", ioe);
        }
    }

    /**
     * Returns the directory containing the given lock file.
     *
     * @param lockFile the lock file being analyzed
     * @return the directory containing the lock file
     */
    private static File getDependencyDirectory(File lockFile) {
        final File folder = lockFile.getParentFile();
        if (!folder.isDirectory()) {
            throw new IllegalArgumentException(String.format("%s should have been a directory.", folder.getAbsolutePath()));
        }
        return folder;
    }
}
