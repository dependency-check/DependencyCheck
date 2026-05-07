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

import org.jspecify.annotations.NonNull;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.exception.WriteLockException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.InvalidSettingException;
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
import java.time.Duration;

public class HostedSuppressionsDataSource extends LocalDataSource {
    /**
     * The default URL to the Hosted Suppressions file.
     */
    public static final String DEFAULT_SUPPRESSIONS_URL = "https://dependency-check.github.io/DependencyCheck/suppressions/publishedSuppressions.xml";

    /**
     * Static logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(HostedSuppressionsDataSource.class);

    /**
     * The configured settings.
     */
    private Settings settings;

    /**
     * Makes a best effort to download the current Hosted suppressions file if configured to do so.
     *
     * @param engine a reference to the ODC Engine
     * @return returns false as no updates are made to the database, just web
     * resources cached locally
     * @throws UpdateException thrown only if the update encountered fatal configuration errors
     */
    @Override
    public boolean update(Engine engine) throws UpdateException {
        try {
            updateUnhandled(engine);
        } catch (UpdateException ex) {
            // only emit a warning, DependencyCheck will continue without taking the latest hosted suppressions into account.
            LOGGER.warn(falsePositivesDueTo("Failed to update hosted suppressions file from remote source"), ex);
        } catch (IOException ex) {
            // Unhandled IOExceptions are fatal configuration errors of a sort
            throw new UpdateException("Unable to determine the local location to cache hosted suppressions", ex);
        }
        return false;
    }

    public static @NonNull String falsePositivesDueTo(String reason) {
        return reason + ", results may contain false positives already resolved by the DependencyCheck project";
    }

    /**
     * Updates the current Hosted Suppressions file if configured to do so; failing if it cannot be done
     *
     * @param engine a reference to the ODC Engine
     * @throws IOException if there is an error determining the local location to cache hosted suppressions
     * @throws UpdateException if the remote update failed for any reason
     */
    public void updateUnhandled(Engine engine) throws IOException, UpdateException {
        this.settings = engine.getSettings();
        final URL url = validatedUrl();
        final File repoFile = validatedRepoFileFrom(url);

        if (isEnabled() && shouldUpdateFromRemote(repoFile)) {
            LOGGER.debug("Begin Hosted Suppressions file update from remote source");
            fetchHostedSuppressions(url, repoFile);
            saveLastUpdated(repoFile);
        }
    }

    private @NonNull URL validatedUrl() throws InvalidSettingException {
        final String configuredUrl = settings.getString(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, DEFAULT_SUPPRESSIONS_URL);
        try {
            return new URL(configuredUrl);
        } catch (MalformedURLException ex) {
            throw new InvalidSettingException(String.format("Invalid URL for Hosted Suppressions file (%s)", configuredUrl), ex);
        }
    }

    public @NonNull File validatedRepoFile() throws IOException {
        return validatedRepoFileFrom(validatedUrl());
    }

    private @NonNull File validatedRepoFileFrom(URL url) throws IOException {
        String fileName = new File(url.getPath()).getName();
        if (fileName.isBlank()) {
            throw new InvalidSettingException("Hosted Suppression URL must imply a filename; even if disabled.");
        }
        return new File(settings.getDataDirectory(), fileName);
    }

    private boolean isEnabled() {
        return settings.getBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, true) && (
                settings.getBoolean(Settings.KEYS.ANALYZER_CPE_SUPPRESSION_ENABLED, true) ||
                        settings.getBoolean(Settings.KEYS.ANALYZER_VULNERABILITY_SUPPRESSION_ENABLED, true));
    }

    private boolean shouldUpdateFromRemote(File repoFile) {
        boolean forceupdate = settings.getBoolean(Settings.KEYS.HOSTED_SUPPRESSIONS_FORCEUPDATE, false);
        boolean autoupdate = settings.getBoolean(Settings.KEYS.AUTO_UPDATE, true);
        Duration validFor = Duration.ofHours(settings.getInt(Settings.KEYS.HOSTED_SUPPRESSIONS_VALID_FOR_HOURS, 2));
        return forceupdate || (autoupdate && isStale(repoFile, validFor));
    }

    /**
     * Fetches the hosted suppressions file
     *
     * @param repoUrl the URL to the hosted suppressions file to use
     * @param repoFile the local file where the hosted suppressions file is to
     * be placed
     * @throws UpdateException thrown if there is an exception during
     * initialization
     */
    @SuppressWarnings("try")
    private void fetchHostedSuppressions(URL repoUrl, File repoFile) throws UpdateException {
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
            final File repo = validatedRepoFile();
            if (repo.exists()) {
                try (WriteLock ignored = new WriteLock(settings, true, repo.getName() + ".lock")) {
                    result = deleteCachedFile(repo);
                }
            }
        } catch (WriteLockException | IOException ex) {
            LOGGER.error("Unable to delete the Hosted suppression file - invalid configuration: {}", ex.toString());
            result = false;
        }
        return result;
    }

    private boolean deleteCachedFile(final File repo) {
        boolean deleted = true;
        try {
            if (Files.deleteIfExists(repo.toPath())) {
                LOGGER.info("Hosted suppression file removed successfully");
            }
        } catch (IOException ex) {
            LOGGER.error("Unable to delete '{}'; please delete the file manually", repo.getAbsolutePath(), ex);
            deleted = false;
        }
        return deleted;
    }
}
