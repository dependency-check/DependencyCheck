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
 * Copyright (c) 2024 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.Properties;

/**
 *
 * @author Jeremy Long
 */
public abstract class LocalDataSource implements CachedWebDataSource {

    /**
     * Static logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(LocalDataSource.class);

    /**
     * Saves the timestamp in a properties file adjacent to the provided repo file
     *
     * @param repo the local file data source
     */
    protected void saveLastUpdated(@NonNull File repo) {
        final File timestampFile = new File(repo + ".properties");
        try (OutputStream out = new FileOutputStream(timestampFile)) {
            final Properties prop = new Properties();
            prop.setProperty("LAST_UPDATED", String.valueOf(System.currentTimeMillis()));
            prop.store(out, null);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Retrieves the last updated date from the local file system (in a file
     * next to the repo file).
     *
     * @param repo the local file data source
     * @return the instant of the last updated date/time
     */
    protected Instant getLastUpdated(@NonNull File repo) {
        long lastUpdatedOn = 0;
        final File timestampFile = new File(repo + ".properties");
        if (timestampFile.isFile()) {
            try (InputStream is = new FileInputStream(timestampFile)) {
                final Properties props = new Properties();
                props.load(is);
                lastUpdatedOn = Long.parseLong(props.getProperty("LAST_UPDATED", "0"));
            } catch (IOException | NumberFormatException ex) {
                LOGGER.debug("error reading timestamp file", ex);
            }
            if (lastUpdatedOn <= 0) {
                //fall back on conversion from file last modified
                lastUpdatedOn = repo.lastModified();
            }
        }
        return Instant.ofEpochMilli(lastUpdatedOn);
    }

    /**
     * Determines if we should update the local data source.
     *
     * @param repo the local file data source
     * @param validFor the duration for which the local data source should be considered valid
     * @return <code>true</code> if an update to the data source should be performed; otherwise <code>false</code>.
     *         If the repo does not exist, or is an empty file, it is considered stale.
     */
    protected boolean isStale(File repo, Duration validFor) {
        boolean stale = true;
        if (repo != null && repo.isFile()) {
            final Instant lastUpdatedOn = getLastUpdated(repo);
            final Instant now = Instant.now();
            LOGGER.debug("{} last updated: {}, now: {}", getClass().getSimpleName(), lastUpdatedOn, now);
            stale = lastUpdatedOn.plus(validFor).isBefore(now);
            if (!stale) {
                LOGGER.info("Should skip {} update since last update was within period {}.", getClass().getSimpleName(), validFor);
            }
        }
        return stale;
    }
}
