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
 * Copyright (c) 2019 Jason Dillon. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.ossindex;

import com.google.common.annotations.VisibleForTesting;
import org.joda.time.Duration;
import org.jspecify.annotations.NonNull;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.ossindex.service.client.OssindexClient;
import org.sonatype.ossindex.service.client.OssindexClientConfiguration;
import org.sonatype.ossindex.service.client.cache.DirectoryCache;
import org.sonatype.ossindex.service.client.internal.OssindexClientImpl;
import org.sonatype.ossindex.service.client.marshal.GsonMarshaller;
import org.sonatype.ossindex.service.client.marshal.Marshaller;
import org.sonatype.ossindex.service.client.transport.AuthConfiguration;
import org.sonatype.ossindex.service.client.transport.Transport;
import org.sonatype.ossindex.service.client.transport.UserAgentSupplier;

import java.io.File;
import java.io.IOException;

/**
 * Produces {@link OssindexClient} instances.
 *
 * @author Jason Dillon
 * @since 5.0.0
 */
public final class OssIndexClientProvider {
    /**
     * Default base URL for Sonatype OSS Index after its migration to part of Sonatype Guide. This overrides the default
     * from {@link OssindexClientConfiguration#DEFAULT_BASE_URL} which is now outdated.
     */
    public static final String DEFAULT_BASE_URL = "https://api.guide.sonatype.com";

    /**
     * Default number of hours to cache entries from OSS Index when the cache is enabled.
     */
    public static final int DEFAULT_CACHE_VALID_FOR_HOURS = 24;

    /**
     * Static logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(OssIndexClientProvider.class);

    /**
     * Private constructor for utility class.
     */
    private OssIndexClientProvider() {
        //private constructor for utility class
    }

    /**
     * Constructs a new OSS Index Client.
     *
     * @param settings the configured settings
     * @return a new OSS Index Client
     */
    public static OssindexClient create(final Settings settings) {
        final OssindexClientConfiguration config = new OssindexClientConfiguration();

        config.setBaseUrl(settings.getString(Settings.KEYS.ANALYZER_OSSINDEX_URL, DEFAULT_BASE_URL));
        config.setAuthConfiguration(new AuthConfiguration(
                settings.getString(Settings.KEYS.ANALYZER_OSSINDEX_USER, ""),
                settings.getString(Settings.KEYS.ANALYZER_OSSINDEX_PASSWORD))
        );

        final int batchSize = settings.getInt(Settings.KEYS.ANALYZER_OSSINDEX_BATCH_SIZE, OssindexClientConfiguration.DEFAULT_BATCH_SIZE);
        config.setBatchSize(batchSize);

        if (settings.getBoolean(Settings.KEYS.ANALYZER_OSSINDEX_USE_CACHE, true)) {
            final DirectoryCache.Configuration cache = new DirectoryCache.Configuration();
            final File data;
            try {
                data = settings.getDataDirectory();
                final File cacheDir = new File(data, "oss_cache");
                if (cacheDir.isDirectory() || cacheDir.mkdirs()) {
                    cache.setBaseDir(cacheDir.toPath());
                    cache.setExpireAfter(Duration.standardHours(settings.getInt(Settings.KEYS.ANALYZER_OSSINDEX_CACHE_VALID_FOR_HOURS, DEFAULT_CACHE_VALID_FOR_HOURS)));
                    config.setCacheConfiguration(cache);
                    LOGGER.debug("OSS Index Cache: {}", cache);
                } else {
                    LOGGER.warn("Unable to use a cache for the OSS Index");
                }
            } catch (IOException ex) {
                LOGGER.warn("Unable to use a cache for the OSS Index", ex);
            }
        }
        // customize User-Agent for use with dependency-check
        final UserAgentSupplier userAgent = new UserAgentSupplier(
                "dependency-check",
                settings.getString(Settings.KEYS.APPLICATION_VERSION, "unknown")
        );

        final Transport transport = new ODCConnectionTransport(config, userAgent);

        final Marshaller marshaller = new GsonMarshaller();

        return newClientFor(config, transport, marshaller);
    }

    @VisibleForTesting
    static @NonNull OssindexClientImpl newClientFor(OssindexClientConfiguration config, Transport transport, Marshaller marshaller) {
        return new OssindexClientImpl(config, transport, marshaller);
    }
}
