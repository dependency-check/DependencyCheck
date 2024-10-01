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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
     * Saves the timestamp in a properties file next to the provided repo file
     *
     * @param repo the local file data source
     * @param timestamp the epoch timestamp to store
     */
    protected void saveLastUpdated(File repo, long timestamp) {
        final File timestampFile = new File(repo + ".properties");
        try (OutputStream out = new FileOutputStream(timestampFile)) {
            final Properties prop = new Properties();
            prop.setProperty("LAST_UPDATED", String.valueOf(timestamp));
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
     * @return the epoch timestamp of the last updated date/time
     */
    protected long getLastUpdated(File repo) {
        long lastUpdatedOn = 0;
        final File timestampFile = new File(repo + ".properties");
        if (timestampFile.isFile()) {
            try (InputStream is = new FileInputStream(timestampFile)) {
                final Properties props = new Properties();
                props.load(is);
                lastUpdatedOn = Integer.parseInt(props.getProperty("LAST_UPDATED", "0"));
            } catch (IOException | NumberFormatException ex) {
                LOGGER.debug("error reading timestamp file", ex);
            }
            if (lastUpdatedOn <= 0) {
                //fall back on conversion from file last modified to storing in the db.
                lastUpdatedOn = repo.lastModified();
            }
        }
        return lastUpdatedOn;
    }
}
