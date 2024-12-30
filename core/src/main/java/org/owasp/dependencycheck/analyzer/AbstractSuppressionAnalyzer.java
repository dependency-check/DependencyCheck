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
import java.util.Set;
import java.util.regex.Pattern;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.update.HostedSuppressionsDataSource;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.exception.WriteLockException;
import org.owasp.dependencycheck.utils.WriteLock;
import org.owasp.dependencycheck.xml.suppression.SuppressionParseException;
import org.owasp.dependencycheck.xml.suppression.SuppressionParser;
import org.owasp.dependencycheck.xml.suppression.SuppressionRule;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

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
     * The key used to store and retrieve the suppression files.
     */
    public static final String SUPPRESSION_OBJECT_KEY = "suppression.rules";

    /**
     * Returns a list of file EXTENSIONS supported by this analyzer.
     *
     * @return a list of file EXTENSIONS supported by this analyzer.
     */
    @SuppressWarnings("SameReturnValue")
    public Set<String> getSupportedExtensions() {
        return null;
    }

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
            throw new InitializationException("Error initializing the suppression analyzer: " + ex.getLocalizedMessage(), ex, true);
        }

        try {
            loadSuppressionData(engine);
        } catch (SuppressionParseException ex) {
            throw new InitializationException("Warn initializing the suppression analyzer: " + ex.getLocalizedMessage(), ex, false);
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
    private void loadSuppressionData(Engine engine) throws SuppressionParseException {
        final List<SuppressionRule> ruleList = new ArrayList<>();
        final SuppressionParser parser = new SuppressionParser();
        final String[] suppressionFilePaths = getSettings().getArray(Settings.KEYS.SUPPRESSION_FILE);
        final List<String> failedLoadingFiles = new ArrayList<>();
        if (suppressionFilePaths != null && suppressionFilePaths.length > 0) {
            // Load all the suppression file paths
            for (final String suppressionFilePath : suppressionFilePaths) {
                try {
                    ruleList.addAll(loadSuppressionFile(parser, suppressionFilePath));
                } catch (SuppressionParseException ex) {
                    final String msg = String.format("Failed to load %s, caused by %s. ", suppressionFilePath, ex.getMessage());
                    failedLoadingFiles.add(msg);
                }
            }
        }

        LOGGER.debug("{} suppression rules were loaded.", ruleList.size());
        if (!ruleList.isEmpty()) {
            if (engine.hasObject(SUPPRESSION_OBJECT_KEY)) {
                @SuppressWarnings("unchecked")
                final List<SuppressionRule> rules = (List<SuppressionRule>) engine.getObject(SUPPRESSION_OBJECT_KEY);
                rules.addAll(ruleList);
            } else {
                engine.putObject(SUPPRESSION_OBJECT_KEY, ruleList);
            }
        }
        if (!failedLoadingFiles.isEmpty()) {
            LOGGER.debug("{} suppression files failed to load.", failedLoadingFiles.size());
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
        final SuppressionParser parser = new SuppressionParser();
        loadPackagedSuppressionBaseData(parser, engine);
        loadHostedSuppressionBaseData(parser, engine);
    }

    /**
     * Loads all the base suppression rules packaged with the application.
     *
     * @param parser The suppression parser to use
     * @param engine a reference the dependency-check engine
     * @throws SuppressionParseException thrown if the XML cannot be parsed.
     */
    private void loadPackagedSuppressionBaseData(final SuppressionParser parser, final Engine engine) throws SuppressionParseException {
        final List<SuppressionRule> ruleList;
        try (InputStream in = FileUtils.getResourceAsStream(BASE_SUPPRESSION_FILE)) {
            if (in == null) {
                throw new SuppressionParseException("Suppression rules `" + BASE_SUPPRESSION_FILE + "` could not be found");
            }
            ruleList = parser.parseSuppressionRules(in);
        } catch (SAXException | IOException ex) {
            throw new SuppressionParseException("Unable to parse the base suppression data file", ex);
        }
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
     * Loads all the base suppression rules from the hosted suppression file
     * generated/updated automatically by the FP Suppression GitHub Action for
     * approved FP suppression.<br>
     * Uses local caching as a fall-back in case the hosted location cannot be
     * accessed, ignore any errors in the loading of the hosted suppression file
     * emitting only a warning that some False Positives may emerge that have
     * already been resolved by the dependency-check project.
     *
     * @param engine a reference the dependency-check engine
     * @param parser The suppression parser to use
     */
    private void loadHostedSuppressionBaseData(final SuppressionParser parser, final Engine engine) {
        final File repoFile;
        boolean repoEmpty = false;
        final boolean enabled = getSettings().getBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
        if (!enabled) {
            return;
        }
        final boolean autoupdate = getSettings().getBoolean(Settings.KEYS.AUTO_UPDATE, true);
        final boolean forceupdate = getSettings().getBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_FORCEUPDATE, false);

        try {
            final String configuredUrl = getSettings().getString(Settings.KEYS.HOSTED_SUPPRESSIONS_URL,
                    HostedSuppressionsDataSource.DEFAULT_SUPPRESSIONS_URL);
            final URL url = new URL(configuredUrl);
            final String fileName = new File(url.getPath()).getName();
            repoFile = new File(getSettings().getDataDirectory(), fileName);
            if (!repoFile.isFile() || repoFile.length() <= 1L) {
                repoEmpty = true;
                LOGGER.warn("Hosted Suppressions file is empty or missing - attempting to force the update");
                getSettings().setBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_FORCEUPDATE, true);
            }
            if ((!autoupdate && forceupdate) || (autoupdate && repoEmpty)) {
                if (engine == null) {
                    LOGGER.warn("Engine was null, this should only happen in tests - skipping forced update");
                } else {
                    repoEmpty = forceUpdateHostedSuppressions(engine, repoFile);
                }
            }
            if (!repoEmpty) {
                loadCachedHostedSuppressionsRules(parser, repoFile, engine);
            } else {
                LOGGER.warn("Empty Hosted Suppression file after update, results may contain false positives "
                        + "already resolved by the DependencyCheck project due to failed download of the hosted suppression file");
            }
        } catch (IOException | InitializationException ex) {
            LOGGER.warn("Unable to load hosted suppressions", ex);
        }
    }

    /**
     * Load the hosted suppression file from the web resource
     *
     * @param parser The suppressionParser to use for loading
     * @param repoFile The cached web resource
     * @param engine a reference the dependency-check engine
     *
     * @throws InitializationException When errors occur trying to create a
     * defensive copy of the web resource before loading
     */
    private void loadCachedHostedSuppressionsRules(final SuppressionParser parser, final File repoFile, final Engine engine)
            throws InitializationException {
        // take a defensive copy to avoid a risk of corrupted file by a competing parallel new download.
        final Path defensiveCopy;
        try (WriteLock lock = new WriteLock(getSettings(), true, repoFile.getName() + ".lock")) {
            defensiveCopy = Files.createTempFile("dc-basesuppressions", ".xml");
            LOGGER.debug("copying hosted suppressions file {} to {}", repoFile.toPath(), defensiveCopy);
            Files.copy(repoFile.toPath(), defensiveCopy, StandardCopyOption.REPLACE_EXISTING);
        } catch (WriteLockException | IOException ex) {
            throw new InitializationException("Failed to copy the hosted suppressions file", ex);
        }

        try (InputStream in = Files.newInputStream(defensiveCopy)) {
            final List<SuppressionRule> ruleList;
            ruleList = parser.parseSuppressionRules(in);
            if (!ruleList.isEmpty()) {
                if (engine.hasObject(SUPPRESSION_OBJECT_KEY)) {
                    @SuppressWarnings("unchecked")
                    final List<SuppressionRule> rules = (List<SuppressionRule>) engine.getObject(SUPPRESSION_OBJECT_KEY);
                    rules.addAll(ruleList);
                } else {
                    engine.putObject(SUPPRESSION_OBJECT_KEY, ruleList);
                }
            }
        } catch (SAXException | IOException ex) {
            LOGGER.warn("Unable to parse the hosted suppressions data file, results may contain false positives already resolved "
                    + "by the DependencyCheck project", ex);
        }
        try {
            Files.delete(defensiveCopy);
        } catch (IOException ex) {
            LOGGER.warn("Could not delete defensive copy of hosted suppressions file {}", defensiveCopy, ex);
        }
    }

    private static boolean forceUpdateHostedSuppressions(final Engine engine, final File repoFile) {
        final HostedSuppressionsDataSource ds = new HostedSuppressionsDataSource();
        boolean repoEmpty = true;
        try {
            ds.update(engine);
            repoEmpty = !repoFile.isFile() || repoFile.length() <= 1L;
        } catch (UpdateException ex) {
            LOGGER.warn("Failed to update the Hosted Suppression file", ex);
        }
        return repoEmpty;
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
                        throw new SuppressionParseException("Unable to download supression file `" + file
                                + "`; received 429 - too many requests", ex1);
                    } catch (ResourceNotFoundException ex1) {
                        throw new SuppressionParseException("Unable to download supression file `" + file
                                + "`; received 404 - resource not found", ex1);
                    } catch (InterruptedException ex1) {
                        Thread.currentThread().interrupt();
                        throw new SuppressionParseException("Unable to download supression file `" + file + "`", ex1);
                    }
                } catch (TooManyRequestsException ex) {
                    throw new SuppressionParseException("Unable to download supression file `" + file
                            + "`; received 429 - too many requests", ex);
                } catch (ResourceNotFoundException ex) {
                    throw new SuppressionParseException("Unable to download supression file `" + file + "`; received 404 - resource not found", ex);
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
            if (file != null) {
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
        LOGGER.warn(String.format(message + " '%s'", suppressionFilePath));
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
