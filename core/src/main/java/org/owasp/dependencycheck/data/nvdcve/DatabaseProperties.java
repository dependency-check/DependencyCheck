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
package org.owasp.dependencycheck.data.nvdcve;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.TreeMap;
import javax.annotation.concurrent.ThreadSafe;

import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.DateUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is a wrapper around a set of properties that are stored in the database.
 * This class is safe to be accessed from multiple threads in parallel.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class DatabaseProperties {

    /**
     * The Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseProperties.class);
    /**
     * The last modified request data for the NVD API.
     */
    public static final String NVD_API_LAST_MODIFIED = "nvd.api.last.modified";
    /**
     * The date the NVD API was last checked for an update.
     */
    public static final String NVD_API_LAST_CHECKED = "nvd.api.last.checked";
    /**
     * The date the NVD cache was last checked for an update.
     */
    public static final String NVD_CACHE_LAST_CHECKED = "nvd.cache.last.checked";
    /**
     * The date the NVD cache data was last modified/updated.
     */
    public static final String NVD_CACHE_LAST_MODIFIED = "nvd.cache.last.modified";
    /**
     * The key for the last time the CPE data was updated.
     */
    public static final String LAST_CPE_UPDATE = "LAST_CPE_UPDATE";
    /**
     * The key for the database schema version.
     */
    public static final String VERSION = "version";
    /**
     * The key for the last check time for the Known Exploited Vulnerabilities.
     */
    public static final String KEV_LAST_CHECKED = "kev.checked";
    /**
     * The key for the version the Known Exploited Vulnerabilities.
     */
    public static final String KEV_VERSION = "kev.version";
    /**
     * A collection of properties about the data.
     */
    private final Properties properties;
    /**
     * A reference to the database.
     */
    private final CveDB cveDB;

    /**
     * Constructs a new data properties object.
     *
     * @param cveDB the database object holding the properties
     */
    DatabaseProperties(CveDB cveDB) {
        this.cveDB = cveDB;
        this.properties = cveDB.getProperties();
    }

    /**
     * Returns whether or not any properties are set.
     *
     * @return whether or not any properties are set
     */
    public synchronized boolean isEmpty() {
        return properties == null || properties.isEmpty();
    }

    /**
     * Saves the key value pair to the properties store.
     *
     * @param key the property key
     * @param value the property value
     */
    public synchronized void save(String key, String value) {
        properties.put(key, value);
        cveDB.saveProperty(key, value);
    }

    /**
     * Returns the property value for the given key. If the key is not contained
     * in the underlying properties null is returned.
     *
     * @param key the property key
     * @return the value of the property
     */
    public synchronized String getProperty(String key) {
        return properties.getProperty(key);
    }

    /**
     * Returns the property value for the given key. If the key is not contained
     * in the underlying properties the default value is returned.
     *
     * @param key the property key
     * @param defaultValue the default value
     * @return the value of the property
     */
    public synchronized String getProperty(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }

    /**
     * Returns the collection of Database Properties as a properties collection.
     *
     * @return the collection of Database Properties
     */
    public synchronized Properties getProperties() {
        return properties;
    }

    /**
     * Returns a map of the meta data from the database properties. This
     * primarily contains timestamps of when the NVD CVE information was last
     * updated.
     *
     * @return a map of the database meta data
     */
    public synchronized Map<String, String> getMetaData() {
        final Map<String, String> map = new TreeMap<>();
        for (Entry<Object, Object> entry : properties.entrySet()) {
            final String key = (String) entry.getKey();
            if (!"version".equals(key)) {
                if (DatabaseProperties.NVD_API_LAST_CHECKED.equals(key)) {
                    map.put("NVD API Last Checked", entry.getValue().toString());

                } else if (DatabaseProperties.NVD_API_LAST_MODIFIED.equals(key)) {
                    map.put("NVD API Last Modified", entry.getValue().toString());

                } else if (DatabaseProperties.NVD_CACHE_LAST_CHECKED.equals(key)) {
                    map.put("NVD Cache Last Checked", entry.getValue().toString());

                } else if (DatabaseProperties.NVD_CACHE_LAST_MODIFIED.equals(key)) {
                    map.put("NVD Cache Last Modified", entry.getValue().toString());
                }
            }
        }
        return map;
    }

    /**
     * Retrieves a zoned date time.
     *
     * @param key the property key
     * @return the zoned date time
     */
    public ZonedDateTime getTimestamp(String key) {
        return DatabaseProperties.getTimestamp(properties, key);
    }

    /**
     * Stores a timestamp.
     *
     * @param key the property key
     * @param timestamp the zoned date time
     */
    public void save(String key, ZonedDateTime timestamp) {
        final DateTimeFormatter dtf = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ssX");
        save(key, dtf.format(timestamp));
    }

    /**
     * Stores a timestamp in the properties file.
     *
     * @param properties the properties to store the timestamp
     * @param key the property key
     * @param timestamp the zoned date time
     */
    public static void setTimestamp(Properties properties, String key, ZonedDateTime timestamp) {
        final DateTimeFormatter dtf = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ssX");
        properties.put(key, dtf.format(timestamp));
    }

    /**
     * Retrieves a zoned date time.
     *
     * @param properties the properties file containing the date time
     * @param key the property key
     * @return the zoned date time
     */
    public static ZonedDateTime getTimestamp(Properties properties, String key) {
        final DateTimeFormatter dtf = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ssX");
        final String val = properties.getProperty(key);
        if (val != null) {
            final String value = properties.getProperty(key);
            return ZonedDateTime.parse(value, dtf);
        }
        return null;
    }

    /**
     * Retrieves a zoned date time.
     *
     * @param properties the properties file containing the date time
     * @param key the property key
     * @return the zoned date time
     */
    public static ZonedDateTime getIsoTimestamp(Properties properties, String key) {
        //final DateTimeFormatter dtf = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ssX");
        final DateTimeFormatter dtf = DateTimeFormatter.ISO_DATE_TIME;
        final String val = properties.getProperty(key);
        if (val != null) {
            final String value = properties.getProperty(key);
            return ZonedDateTime.parse(value, dtf);
        }
        return null;
    }

    /**
     * Returns the database property value in seconds.
     *
     * @param key the key to the property
     * @return the property value in seconds
     */
    public long getPropertyInSeconds(String key) {
        final String value = getProperty(key, "0");
        return DateUtil.getEpochValueInSeconds(value);
    }

}
