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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.annotation.concurrent.ThreadSafe;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.DateUtil;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Checks the gh-pages dependency-check site to determine the current released
 * version number. If the released version number is greater than the running
 * version number a warning is printed recommending that an upgrade be
 * performed.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class EngineVersionCheck implements CachedWebDataSource {

    /**
     * Static logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(EngineVersionCheck.class);
    /**
     * The property key indicating when the last version check occurred.
     */
    public static final String ENGINE_VERSION_CHECKED_ON = "VersionCheckOn";
    /**
     * The property key indicating when the last version check occurred.
     */
    public static final String CURRENT_ENGINE_RELEASE = "CurrentEngineRelease";
    /**
     * The version retrieved from the database properties or web to check
     * against.
     */
    private String updateToVersion;
    /**
     * The configured settings.
     */
    private Settings settings;

    /**
     * Constructs a new engine version check utility for testing.
     *
     * @param settings the configured settings
     */
    protected EngineVersionCheck(Settings settings) {
        this.settings = settings;
    }

    /**
     * Constructs a new engine version check utility.
     */
    public EngineVersionCheck() {
    }

    /**
     * Getter for updateToVersion - only used for testing. Represents the
     * version retrieved from the database.
     *
     * @return the version to test
     */
    protected String getUpdateToVersion() {
        return updateToVersion;
    }

    /**
     * Setter for updateToVersion - only used for testing. Represents the
     * version retrieved from the database.
     *
     * @param version the version to test
     */
    protected void setUpdateToVersion(String version) {
        updateToVersion = version;
    }

    /**
     * Downloads the current released version number and compares it to the
     * running engine's version number. If the released version number is newer
     * a warning is printed recommending an upgrade.
     *
     * @return returns false as no updates are made to the database that would
     * require compaction
     * @throws UpdateException thrown if the local database properties could not
     * be updated
     */
    @Override
    public boolean update(Engine engine) throws UpdateException {
        this.settings = engine.getSettings();
        try {
            final CveDB db = engine.getDatabase();
            final boolean autoupdate = settings.getBoolean(Settings.KEYS.AUTO_UPDATE, true);
            final boolean enabled = settings.getBoolean(Settings.KEYS.UPDATE_VERSION_CHECK_ENABLED, true);
            final String datafeed = settings.getString(Settings.KEYS.NVD_API_DATAFEED_URL);
            /*
             * Only update if auto-update is enabled, the engine check is
             * enabled, and the NVD DataFeed is being used (i.e. the user
             * is likely on a private network). This check is not really needed
             * so we are okay skipping it.
             */
            if (enabled && autoupdate && datafeed != null) {
                LOGGER.debug("Begin Engine Version Check");

                final DatabaseProperties properties = db.getDatabaseProperties();

                final long lastChecked = DateUtil.getEpochValueInSeconds(properties.getProperty(ENGINE_VERSION_CHECKED_ON, "0"));
                final long now = System.currentTimeMillis() / 1000;
                updateToVersion = properties.getProperty(CURRENT_ENGINE_RELEASE, "");
                final String currentVersion = settings.getString(Settings.KEYS.APPLICATION_VERSION, "0.0.0");
                LOGGER.debug("Last checked: {}", lastChecked);
                LOGGER.debug("Now: {}", now);
                LOGGER.debug("Current version: {}", currentVersion);
                final boolean updateNeeded = shouldUpdate(lastChecked, now, properties, currentVersion);
                if (updateNeeded) {
                    LOGGER.warn("A new version of dependency-check is available. Consider updating to version {}.",
                            updateToVersion);
                }
            }
        } catch (DatabaseException ex) {
            LOGGER.debug("Database Exception opening databases to retrieve properties", ex);
            throw new UpdateException("Error occurred updating database properties.");
        }
        return false;
    }

    /**
     * Determines if a new version of the dependency-check engine has been
     * released.
     *
     * @param lastChecked the epoch time of the last version check
     * @param now the current epoch time
     * @param properties the database properties object
     * @param currentVersion the current version of dependency-check
     * @return <code>true</code> if a newer version of the database has been
     * released; otherwise <code>false</code>
     * @throws UpdateException thrown if there is an error connecting to the
     * github documentation site or accessing the local database.
     */
    protected boolean shouldUpdate(final long lastChecked, final long now, final DatabaseProperties properties,
                                   String currentVersion) throws UpdateException {
        //check every 30 days if we know there is an update, otherwise check every 7 days
        final int checkRange = 30;
        if (!DateUtil.withinDateRange(lastChecked, now, checkRange)) {
            LOGGER.debug("Checking web for new version.");
            final String publishedData = getCurrentReleaseVersion();
            if (publishedData != null) {
                final String[] parts = publishedData.split("\n");
                if (parts.length > 1) {
                    final String message = String.join("\n", Arrays.copyOfRange(parts, 1, parts.length)).trim();
                    LOGGER.warn("\n\n*********************************************************\n"
                            + message
                            + "\n*********************************************************\n");
                }
                final String currentRelease = parts[0].trim();
                final DependencyVersion v = new DependencyVersion(currentRelease);
                if (v.getVersionParts() != null && v.getVersionParts().size() >= 3) {
                    updateToVersion = v.toString();
                    if (!currentRelease.equals(updateToVersion)) {
                        properties.save(CURRENT_ENGINE_RELEASE, updateToVersion);
                    }
                    properties.save(ENGINE_VERSION_CHECKED_ON, Long.toString(now));
                }
            }
            LOGGER.debug("Current Release: {}", updateToVersion);
        }
        if (updateToVersion == null) {
            LOGGER.debug("Unable to obtain current release");
            return false;
        }
        final DependencyVersion running = new DependencyVersion(currentVersion);
        final DependencyVersion released = new DependencyVersion(updateToVersion);
        if (running.compareTo(released) < 0) {
            LOGGER.debug("Upgrade recommended");
            return true;
        }
        LOGGER.debug("Upgrade not needed");
        return false;
    }

    /**
     * Retrieves the current released version number from the github
     * documentation site.
     *
     * @return the current released version number
     */
    protected String getCurrentReleaseVersion() {
        try {
            final String str = settings.getString(Settings.KEYS.ENGINE_VERSION_CHECK_URL, "https://dependency-check.github.io/DependencyCheck/current.txt");
            final URL url = new URL(str);
            String releaseVersion = null;
            releaseVersion = Downloader.getInstance().fetchContent(url, StandardCharsets.UTF_8);
            return releaseVersion.trim();
        } catch (TooManyRequestsException ex) {
            LOGGER.debug("Unable to retrieve current release version of dependency-check - downloader failed on HTTP 429 Too many requests");
        } catch (ResourceNotFoundException ex) {
            LOGGER.debug("Unable to retrieve current release version of dependency-check - downloader  failed on HTTP 404 ResourceNotFound");
        } catch (MalformedURLException ex) {
            LOGGER.debug("Unable to retrieve current release version of dependency-check - malformed url?");
        } catch (IOException ex) {
            LOGGER.debug("Unable to retrieve current release version of dependency-check - i/o exception");
        }
        return null;
    }

    @Override
    public boolean purge(Engine engine) {
        return true;
    }
}
