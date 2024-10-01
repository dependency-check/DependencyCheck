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
 * Copyright (c) 2022 Hans Aikema. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.exception.WriteLockException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import org.owasp.dependencycheck.utils.WriteLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;

public class HostedSuppressionsDataSource extends LocalDataSource {

    /**
     * Static logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(HostedSuppressionsDataSource.class);

    /**
     * The configured settings.
     */
    private Settings settings;
    /**
     * The default URL to the Hosted Suppressions file.
     */
    public static final String DEFAULT_SUPPRESSIONS_URL = "https://jeremylong.github.io/DependencyCheck/suppressions/publishedSuppressions.xml";

    /**
     * Downloads the current Hosted suppressions file.
     *
     * @param engine a reference to the ODC Engine
     * @return returns false as no updates are made to the database, just web
     * resources cached locally
     * @throws UpdateException thrown if the update encountered fatal errors
     */
    @Override
    public boolean update(Engine engine) throws UpdateException {
        this.settings = engine.getSettings();
        final String configuredUrl = settings.getString(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, DEFAULT_SUPPRESSIONS_URL);
        final boolean autoupdate = settings.getBoolean(Settings.KEYS.AUTO_UPDATE, true);
        final boolean forceupdate = settings.getBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_FORCEUPDATE, false);
        final boolean cpeSuppressionEnabled = settings.getBoolean(Settings.KEYS.ANALYZER_CPE_SUPPRESSION_ENABLED, true);
        final boolean vulnSuppressionEnabled = settings.getBoolean(Settings.KEYS.ANALYZER_VULNERABILITY_SUPPRESSION_ENABLED, true);
        boolean enabled = settings.getBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, true);
        enabled = enabled && (cpeSuppressionEnabled || vulnSuppressionEnabled);
        try {
            final URL url = new URL(configuredUrl);
            final File filepath = new File(url.getPath());
            final File repoFile = new File(settings.getDataDirectory(), filepath.getName());
            final boolean proceed = enabled && (forceupdate || (autoupdate && shouldUpdate(repoFile)));
            if (proceed) {
                LOGGER.debug("Begin Hosted Suppressions file update");
                fetchHostedSuppressions(settings, url, repoFile);
                saveLastUpdated(repoFile, System.currentTimeMillis() / 1000);
            }
        } catch (UpdateException ex) {
            // only emit a warning, DependencyCheck will continue without taking the latest hosted suppressions into account.
            LOGGER.warn("Failed to update hosted suppressions file, results may contain false positives already resolved by the "
                    + "DependencyCheck project", ex);
        } catch (MalformedURLException ex) {
            throw new UpdateException(String.format("Invalid URL for Hosted Suppressions file (%s)", configuredUrl), ex);
        } catch (IOException ex) {
            throw new UpdateException("Unable to get the data directory", ex);
        }
        return false;
    }

    /**
     * Determines if the we should update the Hosted Suppressions file.
     *
     * @param repo the Hosted Suppressions file.
     * @return <code>true</code> if an update to the Hosted Suppressions file
     * should be performed; otherwise <code>false</code>
     * @throws NumberFormatException thrown if an invalid value is contained in
     * the database properties
     */
    protected boolean shouldUpdate(File repo) throws NumberFormatException {
        boolean proceed = true;
        if (repo != null && repo.isFile()) {
            final int validForHours = settings.getInt(Settings.KEYS.HOSTED_SUPPRESSIONS_VALID_FOR_HOURS, 2);
            final long lastUpdatedOn = getLastUpdated(repo);
            final long now = System.currentTimeMillis();
            LOGGER.debug("Last updated: {}", lastUpdatedOn);
            LOGGER.debug("Now: {}", now);
            final long msValid = validForHours * 60L * 60L * 1000L;
            proceed = (now - lastUpdatedOn) > msValid;
            if (!proceed) {
                LOGGER.info("Skipping Hosted Suppressions file update since last update was within {} hours.", validForHours);
            }
        }
        return proceed;
    }

    /**
     * Fetches the hosted suppressions file
     *
     * @param settings a reference to the dependency-check settings
     * @param repoUrl the URL to the hosted suppressions file to use
     * @param repoFile the local file where the hosted suppressions file is to
     * be placed
     * @throws UpdateException thrown if there is an exception during
     * initialization
     */
    @SuppressWarnings("try")
    private void fetchHostedSuppressions(Settings settings, URL repoUrl, File repoFile) throws UpdateException {
        try (WriteLock ignored = new WriteLock(settings, true, repoFile.getName() + ".lock")) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Hosted Suppressions URL: {}", repoUrl.toExternalForm());
            }
            Downloader.getInstance().fetchFile(repoUrl, repoFile);
        } catch (IOException | TooManyRequestsException | ResourceNotFoundException | WriteLockException ex) {
            throw new UpdateException("Failed to update the hosted suppressions file", ex);
        }
    }

    @Override
    @SuppressWarnings("try")
    public boolean purge(Engine engine) {
        this.settings = engine.getSettings();
        boolean result = true;
        try {
            final URL repoUrl = new URL(settings.getString(Settings.KEYS.HOSTED_SUPPRESSIONS_URL,
                    DEFAULT_SUPPRESSIONS_URL));
            final String filename = new File(repoUrl.getPath()).getName();
            final File repo = new File(settings.getDataDirectory(), filename);
            if (repo.exists()) {
                try (WriteLock ignored = new WriteLock(settings, true, filename + ".lock")) {
                    result = deleteCachedFile(repo);
                }
            }
        } catch (WriteLockException | IOException ex) {
            LOGGER.error("Unable to delete the Hosted suppression file - invalid configuration");
            result = false;
        }
        return result;
    }

    private boolean deleteCachedFile(final File repo) {
        boolean deleted = true;
        try {
            Files.delete(repo.toPath());
            LOGGER.info("Hosted suppression file removed successfully");
        } catch (IOException ex) {
            LOGGER.error("Unable to delete '{}'; please delete the file manually", repo.getAbsolutePath(), ex);
            deleted = false;
        }
        return deleted;
    }
}
