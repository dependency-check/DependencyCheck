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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.google.common.annotations.VisibleForTesting;
import org.jspecify.annotations.NonNull;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.update.HostedSuppressionsDataSource;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.exception.WriteLockException;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import org.owasp.dependencycheck.utils.WriteLock;
import org.owasp.dependencycheck.xml.suppression.SuppressionParseException;
import org.owasp.dependencycheck.xml.suppression.SuppressionParser;
import org.owasp.dependencycheck.xml.suppression.SuppressionRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import javax.annotation.concurrent.ThreadSafe;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static org.owasp.dependencycheck.data.update.HostedSuppressionsDataSource.falsePositivesDueTo;

/**
 * Abstract base suppression analyzer that contains methods for parsing the
 * suppression XML file.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public abstract class AbstractSuppressionAnalyzer extends AbstractAnalyzer {

    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractSuppressionAnalyzer.class);
    /**
     * The file name of the base suppression XML file.
     */
    private static final String BASE_SUPPRESSION_FILE = "dependencycheck-base-suppression.xml";
    /**
     * The file name of the snapshot of the hosted suppression XML file.
     */
    private static final String HOSTED_SUPPRESSION_SNAPSHOT_FILE = "dependencycheck-hosted-suppression-snapshot.xml";
    /**
     * The key used to store and retrieve the suppression files.
     */
    public static final String SUPPRESSION_OBJECT_KEY = "suppression.rules";

    /**
     * The prepare method loads the suppression XML file.
     *
     * @param engine a reference the dependency-check engine
     * @throws InitializationException thrown if there is an exception
     */
    @Override
    public synchronized void prepareAnalyzer(Engine engine) throws InitializationException {
        if (engine.hasObject(SUPPRESSION_OBJECT_KEY)) {
            return;
        }
        try {
            loadSuppressionBaseData(engine);
        } catch (SuppressionParseException ex) {
            throw new InitializationException("Error initializing the suppression analyzer base data: " + ex, ex, true);
        }

        try {
            loadSuppressionUserData(engine);
        } catch (SuppressionParseException ex) {
            throw new InitializationException("Warn initializing the suppression analyzer user data: " + ex, ex, false);
        }
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (engine == null) {
            return;
        }
        @SuppressWarnings("unchecked")
        final List<SuppressionRule> rules = (List<SuppressionRule>) engine.getObject(SUPPRESSION_OBJECT_KEY);
        if (rules.isEmpty()) {
            return;
        }
        for (SuppressionRule rule : rules) {
            if (filter(rule)) {
                rule.process(dependency);
            }
        }
    }

    /**
     * Determines whether a suppression rule should be retained when filtering a
     * set of suppression rules for a concrete suppression analyzer.
     *
     * @param rule the suppression rule to evaluate
     * @return <code>true</code> if the rule should be retained; otherwise
     * <code>false</code>
     */
    abstract boolean filter(SuppressionRule rule);

    /**
     * Loads all the suppression rules files configured in the {@link Settings}.
     *
     * @param engine a reference to the ODC engine.
     * @throws SuppressionParseException thrown if the XML cannot be parsed.
     */
    private void loadSuppressionUserData(Engine engine) throws SuppressionParseException {
        final SuppressionParser parser = new SuppressionParser();
        final String[] suppressionFilePaths = getSettings().getArray(Settings.KEYS.SUPPRESSION_FILE);
        final List<String> failedLoadingFiles = new ArrayList<>();
        if (suppressionFilePaths != null && suppressionFilePaths.length > 0) {
            final List<SuppressionRule> ruleList = new ArrayList<>();
            // Load all the suppression file paths
            for (final String suppressionFilePath : suppressionFilePaths) {
                try {
                    ruleList.addAll(loadSuppressionFile(parser, suppressionFilePath));
                } catch (SuppressionParseException ex) {
                    final String msg = String.format("Failed to load %s, caused by %s. ", suppressionFilePath, ex.getMessage());
                    failedLoadingFiles.add(msg);
                }
            }
            LOGGER.debug("{} user suppression rules were loaded from {} sources.", ruleList.size(), suppressionFilePaths.length - failedLoadingFiles.size());
            appendRules(engine, ruleList);
        }

        if (!failedLoadingFiles.isEmpty()) {
            LOGGER.debug("{} user suppression files failed to load.", failedLoadingFiles.size());
            final StringBuilder sb = new StringBuilder();
            failedLoadingFiles.forEach(sb::append);
            throw new SuppressionParseException(sb.toString());
        }
    }

    /**
     * Loads all the base suppression rules files.
     *
     * @param engine a reference the dependency-check engine
     * @throws SuppressionParseException thrown if the XML cannot be parsed.
     */
    private void loadSuppressionBaseData(final Engine engine) throws SuppressionParseException {
        loadPackagedBaseSuppressionData(engine);
        loadHostedSuppressionBaseData(engine);
    }

    /**
     * Loads the suppression rules packaged with the application.
     *
     * @param engine a reference the dependency-check engine
     * @throws SuppressionParseException thrown if the XML cannot be parsed.
     */
    @VisibleForTesting
    void loadPackagedBaseSuppressionData(final Engine engine) throws SuppressionParseException {
        List<SuppressionRule> ruleList;
        URL baseSuppressionURL = getPackagedFile(BASE_SUPPRESSION_FILE);
        try (InputStream in = baseSuppressionURL.openStream()) {
            ruleList = new SuppressionParser().parseSuppressionRules(in);
            LOGGER.debug("{} base suppression rules were loaded.", ruleList.size());
            appendRules(engine, ruleList);
        } catch (SAXException | IOException ex) {
            throw new SuppressionParseException("Unable to parse the base suppression data file", ex);
        }
    }

    private static @NonNull URL getPackagedFile(String packagedFileName) throws SuppressionParseException {
        final URL jarLocation = AbstractSuppressionAnalyzer.class.getProtectionDomain().getCodeSource().getLocation();
        String suppressionFileLocation = jarLocation.getFile();
        if (suppressionFileLocation.endsWith(".jar")) {
            suppressionFileLocation = "jar:file:" + suppressionFileLocation + "!/" + packagedFileName;
        } else if (suppressionFileLocation.startsWith("nested:") && suppressionFileLocation.endsWith(".jar!/")) {
            // suppressionFileLocation -> nested:/app/app.jar/!BOOT-INF/lib/dependency-check-core-<version>.jar!/
            // goal->                 jar:nested:/app/app.jar/!BOOT-INF/lib/dependency-check-core-<version>.jar!/dependencycheck-base-suppression.xml
            suppressionFileLocation = "jar:" + suppressionFileLocation + packagedFileName;
        } else {
            suppressionFileLocation = "file:" + suppressionFileLocation + packagedFileName;
        }
        try {
            return new URL(suppressionFileLocation);
        } catch (MalformedURLException e) {
            throw new SuppressionParseException("Unable to load the packaged file: " + packagedFileName, e);
        }
    }

    /**
     * Loads all the base suppression rules from the hosted suppression file
     * generated/updated automatically by the FP Suppression GitHub Action for
     * approved FP suppression.<br>
     * Uses local caching as a fall-back in case the hosted location cannot be
     * accessed, ignore any errors in the loading of the hosted suppression file
     * emitting only a warning that some False Positives may emerge that have
     * already been resolved by the dependency-check project.
     *
     * @param engine a reference the dependency-check engine
     */
    @VisibleForTesting
    void loadHostedSuppressionBaseData(final Engine engine) {
        try {
            // Try remote update if enabled and stale or forced by user
            File repoFile = tryRemoteHostedSuppressionsFetchIfConfigured(engine);

            // If still empty after update attempt; utilize the snapshot hosted suppression file
            //
            // Note that this local fallback will run regardless of whether hosted suppressions are "enabled" or the
            // value of autoUpdate, forceupdate etc since this is an offline operation similar to regular "base" suppressions.
            if (isRepoEmpty(repoFile)) {
                LOGGER.debug("Hosted suppressions not found locally; attempting fallback to store packaged snapshot from this Dependency-Check release at {}...", repoFile.toPath());
                URL hostedSuppressionSnapshotURL = getPackagedFile(HOSTED_SUPPRESSION_SNAPSHOT_FILE);
                try (InputStream in = hostedSuppressionSnapshotURL.openStream()) {
                    Files.copy(in, repoFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
                LOGGER.info(falsePositivesDueTo("Hosted suppressions using snapshot as of this Dependency-Check release"));
            }

            loadCachedHostedSuppressionsRules(repoFile, engine);

        } catch (IOException | InitializationException ex) {
            LOGGER.warn(falsePositivesDueTo("Unable to load hosted suppressions from either remote source or packaged snapshot"), ex);
        }
    }

    private static boolean isRepoEmpty(File repoFile) {
        return !repoFile.isFile() || repoFile.length() <= 1L;
    }

    /**
     * If configured to do so, try fetching hosted suppressions from the configured remote source.
     * @return The local cached repoFile the suppressions are to be loaded from. Note that on return this may still not be created.
     * @throws IOException only if settings are invalid to handle hosted suppressions either remotely or locally
     */
    private File tryRemoteHostedSuppressionsFetchIfConfigured(Engine engine) throws IOException {
        HostedSuppressionsDataSource ds = new HostedSuppressionsDataSource();
        try {
            ds.updateUnhandled(engine);
        } catch (UpdateException ex) {
            LOGGER.warn(falsePositivesDueTo("Failed to update hosted suppressions file from remote source"), ex);
        }
        return ds.validatedRepoFile();
    }

    /**
     * Load the hosted suppression file from the web resource
     *
     * @param repoFile The cached web resource
     * @param engine a reference the dependency-check engine
     *
     * @throws InitializationException When errors occur trying to create a
     * defensive copy of the web resource before loading
     */
    private void loadCachedHostedSuppressionsRules(final File repoFile, final Engine engine)
            throws InitializationException {
        // take a defensive copy to avoid a risk of corrupted file by a competing parallel new download.
        final Path defensiveCopy;
        try (WriteLock ignored = new WriteLock(getSettings(), true, repoFile.getName() + ".lock")) {
            defensiveCopy = Files.createTempFile("dc-basesuppressions", ".xml");
            LOGGER.debug("copying hosted suppressions file {} to {}", repoFile.toPath(), defensiveCopy);
            Files.copy(repoFile.toPath(), defensiveCopy, StandardCopyOption.REPLACE_EXISTING);
        } catch (WriteLockException | IOException ex) {
            throw new InitializationException("Failed to copy the hosted suppressions file", ex);
        }

        try (InputStream in = Files.newInputStream(defensiveCopy)) {
            final List<SuppressionRule> ruleList;
            ruleList = new SuppressionParser().parseSuppressionRules(in);
            LOGGER.debug("{} hosted suppression rules were loaded.", ruleList.size());
            appendRules(engine, ruleList);

        } catch (SAXException | IOException ex) {
            LOGGER.warn(falsePositivesDueTo("Unable to parse the hosted suppressions data file at {}"), repoFile.getPath(), ex);
        }
        try {
            Files.delete(defensiveCopy);
        } catch (IOException ex) {
            LOGGER.warn("Could not delete defensive copy of hosted suppressions file {}", defensiveCopy, ex);
        }
    }

    private void appendRules(Engine engine, List<SuppressionRule> ruleList) {
        if (!ruleList.isEmpty()) {
            if (engine.hasObject(SUPPRESSION_OBJECT_KEY)) {
                @SuppressWarnings("unchecked")
                final List<SuppressionRule> rules = (List<SuppressionRule>) engine.getObject(SUPPRESSION_OBJECT_KEY);
                rules.addAll(ruleList);
            } else {
                engine.putObject(SUPPRESSION_OBJECT_KEY, ruleList);
            }
        }
    }

    /**
     * Load a single suppression rules file from the path provided using the
     * parser provided.
     *
     * @param parser the parser to use for loading the file
     * @param suppressionFilePath the path to load
     * @return the list of loaded suppression rules
     * @throws SuppressionParseException thrown if the suppression file cannot
     * be loaded and parsed.
     */
    private List<SuppressionRule> loadSuppressionFile(final SuppressionParser parser,
            final String suppressionFilePath) throws SuppressionParseException {
        LOGGER.debug("Loading suppression rules from '{}'", suppressionFilePath);
        final List<SuppressionRule> list = new ArrayList<>();
        File file = null;
        boolean deleteTempFile = false;
        try {
            final Pattern uriRx = Pattern.compile("^(https?|file):.*", Pattern.CASE_INSENSITIVE);
            if (uriRx.matcher(suppressionFilePath).matches()) {
                deleteTempFile = true;
                file = getSettings().getTempFile("suppression", "xml");
                final URL url = new URL(suppressionFilePath);
                try {
                    Downloader.getInstance().fetchFile(url, file, false, Settings.KEYS.SUPPRESSION_FILE_USER,
                            Settings.KEYS.SUPPRESSION_FILE_PASSWORD, Settings.KEYS.SUPPRESSION_FILE_BEARER_TOKEN);
                } catch (DownloadFailedException ex) {
                    LOGGER.trace("Failed download suppression file - first attempt", ex);
                    try {
                        Thread.sleep(500);
                        Downloader.getInstance().fetchFile(url, file, true, Settings.KEYS.SUPPRESSION_FILE_USER,
                                Settings.KEYS.SUPPRESSION_FILE_PASSWORD, Settings.KEYS.SUPPRESSION_FILE_BEARER_TOKEN);
                    } catch (TooManyRequestsException ex1) {
                        throw new SuppressionParseException("Unable to download suppression file `" + file
                                + "`; received 429 - too many requests", ex1);
                    } catch (ResourceNotFoundException ex1) {
                        throw new SuppressionParseException("Unable to download suppression file `" + file
                                + "`; received 404 - resource not found", ex1);
                    } catch (InterruptedException ex1) {
                        Thread.currentThread().interrupt();
                        throw new SuppressionParseException("Unable to download suppression file `" + file + "`", ex1);
                    }
                } catch (TooManyRequestsException ex) {
                    throw new SuppressionParseException("Unable to download suppression file `" + file
                            + "`; received 429 - too many requests", ex);
                } catch (ResourceNotFoundException ex) {
                    throw new SuppressionParseException("Unable to download suppression file `" + file + "`; received 404 - resource not found", ex);
                }
            } else {
                file = new File(suppressionFilePath);

                if (!file.exists()) {
                    try (InputStream suppressionFromClasspath = FileUtils.getResourceAsStream(suppressionFilePath)) {
                        deleteTempFile = true;
                        file = getSettings().getTempFile("suppression", "xml");
                        try {
                            Files.copy(suppressionFromClasspath, file.toPath());
                        } catch (IOException ex) {
                            throwSuppressionParseException("Unable to locate suppression file in classpath", ex, suppressionFilePath);
                        }
                    }
                }
            }
            if (!file.exists()) {
                final String msg = String.format("Suppression file '%s' does not exist", file.getPath());
                LOGGER.warn(msg);
                throw new SuppressionParseException(msg);
            }
            try {
                list.addAll(parser.parseSuppressionRules(file));
            } catch (SuppressionParseException ex) {
                LOGGER.warn("Unable to parse suppression xml file '{}'", file.getPath());
                LOGGER.warn(ex.getMessage());
                throw ex;
            }
        } catch (DownloadFailedException ex) {
            throwSuppressionParseException("Unable to fetch the configured suppression file", ex, suppressionFilePath);
        } catch (MalformedURLException ex) {
            throwSuppressionParseException("Configured suppression file has an invalid URL", ex, suppressionFilePath);
        } catch (SuppressionParseException ex) {
            throw ex;
        } catch (IOException ex) {
            throwSuppressionParseException("Unable to read suppression file", ex, suppressionFilePath);
        } finally {
            if (deleteTempFile && file != null) {
                FileUtils.delete(file);
            }
        }
        return list;
    }

    /**
     * Utility method to throw parse exceptions.
     *
     * @param message the exception message
     * @param exception the cause of the exception
     * @param suppressionFilePath the path file
     * @throws SuppressionParseException throws the generated
     * SuppressionParseException
     */
    private void throwSuppressionParseException(String message, Exception exception, String suppressionFilePath) throws SuppressionParseException {
        LOGGER.warn("{} [{}]", message, suppressionFilePath);
        LOGGER.debug("", exception);
        throw new SuppressionParseException(message, exception);
    }

    /**
     * Returns the number of suppression rules currently loaded in the engine.
     *
     * @param engine a reference to the ODC engine
     * @return the count of rules loaded
     */
    public static int getRuleCount(Engine engine) {
        if (engine.hasObject(SUPPRESSION_OBJECT_KEY)) {
            @SuppressWarnings("unchecked")
            final List<SuppressionRule> rules = (List<SuppressionRule>) engine.getObject(SUPPRESSION_OBJECT_KEY);
            return rules.size();
        }
        return 0;
    }
}
