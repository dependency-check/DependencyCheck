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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cache;

import io.github.jeremylong.jcs3.slf4j.Slf4jAdapter;
import io.github.jeremylong.jcs3.slf4j.Slf4jLogFactory;
import org.apache.commons.jcs3.JCS;
import org.apache.commons.jcs3.access.exception.CacheException;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.xml.pom.Model;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Properties;

/**
 * Factory to instantiate cache repositories.
 *
 * @author Jeremy Long
 */
public class DataCacheFactory {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DataCacheFactory.class);
    /**
     * The cache directory.
     */
    private static final String CACHE_DIRECTORY = "cache";
    /**
     * The cache properties.
     */
    private static final String CACHE_PROPERTIES = "dependencycheck-cache.properties";
    /**
     * Whether or not JCS has been initialized.
     */
    private static Boolean initialized = false;

    /**
     * The types of caches that can be instantiated.
     */
    private enum CacheType {
        /**
         * Used to store node audit analysis.
         */
        NODEAUDIT,
        /**
         * Used to store the results of searching Maven Central.
         */
        CENTRAL,
        /**
         * Used to store POM files retrieved from central.
         */
        POM
    }

    private static synchronized void ensureInitialized(Settings settings) {
        if (!initialized) {
            JCS.setLogSystem(new Slf4jLogFactory().getName());
            if (!LOGGER.isTraceEnabled()) {
                Slf4jAdapter.muteLogging(true);
            }

            final File cacheDirectory;
            try {
                cacheDirectory = new File(settings.getDataDirectory(), CACHE_DIRECTORY);
            } catch (IOException ex) {
                throw new CacheException("Unable to obtain disk cache directory path", ex);
            }
            if (!cacheDirectory.isDirectory() && !cacheDirectory.mkdirs()) {
                throw new CacheException("Unable to create disk cache: " + cacheDirectory);
            }
            try (InputStream in = FileUtils.getResourceAsStream(CACHE_PROPERTIES)) {
                final Properties properties = new Properties();
                properties.load(in);
                properties.put("jcs.auxiliary.ODC.attributes.DiskPath", cacheDirectory.getCanonicalPath());
                for (CacheType t : CacheType.values()) {
                    final File fp = new File(cacheDirectory, t.toString());
                    properties.put("jcs.auxiliary." + t + ".attributes.DiskPath", fp.getCanonicalPath());
                }

                JCS.setConfigProperties(properties);
                initialized = true;
            } catch (IOException ex) {
                throw new CacheException("Error creating disk cache", ex);
            }
        }
    }

    /**
     * Creates the data cache factory.
     *
     * @param settings the configuration settings
     */
    public DataCacheFactory(Settings settings) {
        ensureInitialized(settings);
    }

    /**
     * Returns the data cache for Node Audit.
     *
     * @return a references to the data cache for Node Audit
     */
    public DataCache<List<Advisory>> getNodeAuditCache() {
        try {
            return new DataCache<>(JCS.getInstance("NODEAUDIT"));
        } catch (Throwable ex) {
            //some reports of class not found exception, log and disable the cache.
            if (ex instanceof CacheException) {
                throw ex;
            }
            LOGGER.debug("Error constructing cache for node audit files", ex);
            throw new CacheException(ex);
        }
    }

    /**
     * Returns the data cache for POM files.
     *
     * @return a references to the data cache for POM files
     */
    public DataCache<Model> getPomCache() {
        try {
            return new DataCache<>(JCS.getInstance("POM"));
        } catch (Throwable ex) {
            //some reports of class not found exception, log and disable the cache.
            if (ex instanceof CacheException) {
                throw ex;
            }
            LOGGER.debug("Error constructing cache for POM files", ex);
            throw new CacheException(ex);
        }
    }

    /**
     * Returns the data cache for Central search.
     *
     * @return a references to the data cache for Central search
     */
    public DataCache<List<MavenArtifact>> getCentralCache() {
        try {
            return new DataCache<>(JCS.getInstance("CENTRAL"));
        } catch (Throwable ex) {
            //some reports of class not found exception, log and disable the cache.
            if (ex instanceof CacheException) {
                throw ex;
            }
            LOGGER.debug("Error constructing cache for Central files", ex);
            throw new CacheException(ex);
        }
    }
}
