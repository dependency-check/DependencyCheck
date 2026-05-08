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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
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

import javax.annotation.concurrent.ThreadSafe;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;

import static org.owasp.dependencycheck.utils.FileUtils.existsWithContent;

/**
 * Downloads a local copy of the RetireJS repository.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class RetireJSDataSource extends LocalDataSource {
    /**
     * The default URL to the RetireJS JavaScript repository.
     */
    private static final String DEFAULT_JS_URL = "https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json";
    /**
     * Static logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(RetireJSDataSource.class);
    /**
     * The configured settings.
     */
    private Settings settings;

    /**
     * Constructs a new engine version check utility.
     */
    public RetireJSDataSource() {
    }

    /**
     * Downloads the current RetireJS data source.
     *
     * @param engine a reference to the ODC Engine
     * @return returns false as no updates are made to the database
     * @throws UpdateException thrown if the update failed
     */
    @Override
    public boolean update(Engine engine) throws UpdateException {
        this.settings = engine.getSettings();
        final URL url = validatedUrl();
        final File repoFile = validatedRepoFileFrom(url);
        if (isEnabled() && shouldUpdateFromRemote(repoFile)) {
            LOGGER.debug("Begin RetireJS Update");
            initializeRetireJsRepo(settings, url, repoFile);
            saveLastUpdated(repoFile);
        }
        return false;
    }

    private @NonNull URL validatedUrl() throws UpdateException {
        final String configuredUrl = settings.getString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, DEFAULT_JS_URL);
        try {
            return new URL(configuredUrl);
        } catch (MalformedURLException ex) {
            throw new UpdateException(String.format("Invalid URL for RetireJS repository (%s)", configuredUrl), ex);
        }
    }

    public @NonNull File validatedRepoFile() throws UpdateException {
        return validatedRepoFileFrom(validatedUrl());
    }

    private @NonNull File validatedRepoFileFrom(URL url) throws UpdateException {
        try {
            String fileName = new File(url.getPath()).getName();
            if (fileName.isBlank()) {
                throw new InvalidSettingException("RetireJS URL must imply a filename.");
            }
            return new File(settings.getDataDirectory(), fileName);
        } catch (IOException ex) {
            throw new UpdateException("Unable to determine the local location to cache RetireJS repo", ex);
        }
    }

    private boolean isEnabled() {
        return settings.getBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
    }

    private boolean shouldUpdateFromRemote(File repoFile) {
        boolean forceupdate = settings.getBoolean(Settings.KEYS.ANALYZER_RETIREJS_FORCEUPDATE, false);
        boolean autoupdate = settings.getBoolean(Settings.KEYS.AUTO_UPDATE, true);
        Duration validFor = Duration.ofHours(settings.getInt(Settings.KEYS.ANALYZER_RETIREJS_REPO_VALID_FOR_HOURS, 24));
        return forceupdate || !existsWithContent(repoFile) || (autoupdate && isStale(repoFile, validFor));
    }

    /**
     * Initializes the local RetireJS repository
     *
     * @param settings a reference to the dependency-check settings
     * @param repoUrl the URL to the RetireJS repository to use
     * @param repoFile the filename to use for the RetireJS repository
     * @throws UpdateException thrown if there is an exception during initialization
     */
    @SuppressWarnings("try")
    private void initializeRetireJsRepo(Settings settings, URL repoUrl, File repoFile) throws UpdateException {
        try (WriteLock lock = new WriteLock(settings, true, repoFile.getName() + ".lock")) {
            LOGGER.debug("RetireJS Repo URL: {}", repoUrl.toExternalForm());
            Downloader.getInstance().fetchFile(repoUrl, repoFile);
        } catch (IOException | TooManyRequestsException | ResourceNotFoundException | WriteLockException ex) {
            throw new UpdateException("Failed to initialize the RetireJS repo", ex);
        }
    }

    @Override
    @SuppressWarnings("try")
    public boolean purge(Engine engine) {
        this.settings = engine.getSettings();
        boolean result = true;
        try {
            final File dataDir = engine.getSettings().getDataDirectory();
            final URL repoUrl = new URL(engine.getSettings().getString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, DEFAULT_JS_URL));
            final String filename = repoUrl.getFile().substring(repoUrl.getFile().lastIndexOf("/") + 1);
            final File repo = new File(dataDir, filename);
            if (repo.exists()) {
                try (WriteLock lock = new WriteLock(settings, true, filename + ".lock")) {
                    if (repo.delete()) {
                        LOGGER.info("RetireJS repo removed successfully");
                    } else {
                        LOGGER.error("Unable to delete '{}'; please delete the file manually", repo.getAbsolutePath());
                        result = false;
                    }
                }
            }
        } catch (WriteLockException | IOException ex) {
            LOGGER.error("Unable to delete the RetireJS repo - invalid configuration");
            result = false;
        }
        return result;
    }
}
