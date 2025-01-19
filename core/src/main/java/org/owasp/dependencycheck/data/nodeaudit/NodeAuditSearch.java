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
 * Copyright (c) 2018 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.concurrent.ThreadSafe;

import org.apache.hc.client5.http.HttpResponseException;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.message.BasicHeader;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.json.JsonObject;
import org.apache.commons.jcs3.access.exception.CacheException;

import static org.owasp.dependencycheck.analyzer.NodeAuditAnalyzer.DEFAULT_URL;

import org.owasp.dependencycheck.analyzer.exception.SearchException;
import org.owasp.dependencycheck.analyzer.exception.UnexpectedAnalysisException;
import org.owasp.dependencycheck.data.cache.DataCache;
import org.owasp.dependencycheck.data.cache.DataCacheFactory;
import org.owasp.dependencycheck.utils.Checksum;

/**
 * Class of methods to search via Node Audit API.
 *
 * @author Steve Springett
 */
@ThreadSafe
public class NodeAuditSearch {

    /**
     * The URL for the public Node Audit API.
     */
    private final URL nodeAuditUrl;

    /**
     * Whether to use the Proxy when making requests.
     */
    private final boolean useProxy;
    /**
     * The configured settings.
     */
    private final Settings settings;
    /**
     * Used for logging.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NodeAuditSearch.class);
    /**
     * Persisted disk cache for `npm audit` results.
     */
    private DataCache<List<Advisory>> cache;

    /**
     * Creates a NodeAuditSearch for the given repository URL.
     *
     * @param settings the configured settings
     * @throws java.net.MalformedURLException thrown if the configured URL is
     * invalid
     */
    public NodeAuditSearch(Settings settings) throws MalformedURLException {
        final String searchUrl = settings.getString(Settings.KEYS.ANALYZER_NODE_AUDIT_URL, DEFAULT_URL);
        LOGGER.debug("Node Audit Search URL: {}", searchUrl);
        this.nodeAuditUrl = new URL(searchUrl);
        this.settings = settings;
        if (null != settings.getString(Settings.KEYS.PROXY_SERVER)) {
            useProxy = true;
            LOGGER.debug("Using proxy");
        } else {
            useProxy = false;
            LOGGER.debug("Not using proxy");
        }
        if (settings.getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_USE_CACHE, true)) {
            try {
                final DataCacheFactory factory = new DataCacheFactory(settings);
                cache = factory.getNodeAuditCache();
            } catch (CacheException ex) {
                settings.setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_USE_CACHE, false);
                LOGGER.debug("Error creating cache, disabling caching", ex);
            }
        }
    }

    /**
     * Submits the package.json file to the Node Audit API and returns a list of
     * zero or more Advisories.
     *
     * @param packageJson the package.json file retrieved from the Dependency
     * @return a List of zero or more Advisory object
     * @throws SearchException if Node Audit API is unable to analyze the
     * package
     * @throws IOException if it's unable to connect to Node Audit API
     */
    public List<Advisory> submitPackage(JsonObject packageJson) throws SearchException, IOException {
        String key = null;
        if (cache != null) {
            key = Checksum.getSHA256Checksum(packageJson.toString());
            final List<Advisory> cached = cache.get(key);
            if (cached != null) {
                LOGGER.debug("cache hit for node audit: " + key);
                return cached;
            }
        }
        return submitPackage(packageJson, key, 0);
    }

    /**
     * Submits the package.json file to the Node Audit API and returns a list of
     * zero or more Advisories.
     *
     * @param packageJson the package.json file retrieved from the Dependency
     * @param key the key for the cache entry
     * @param count the current retry count
     * @return a List of zero or more Advisory object
     * @throws SearchException if Node Audit API is unable to analyze the
     * package
     * @throws IOException if it's unable to connect to Node Audit API
     */
    private List<Advisory> submitPackage(JsonObject packageJson, String key, int count) throws SearchException, IOException {
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("----------------------------------------");
            LOGGER.trace("Node Audit Payload:");
            LOGGER.trace(packageJson.toString());
            LOGGER.trace("----------------------------------------");
            LOGGER.trace("----------------------------------------");
        }
        final List<Header> additionalHeaders = new ArrayList<>();
        additionalHeaders.add(new BasicHeader(HttpHeaders.USER_AGENT, "npm/6.1.0 node/v10.5.0 linux x64"));
        additionalHeaders.add(new BasicHeader("npm-in-ci", "false"));
        additionalHeaders.add(new BasicHeader("npm-scope", ""));
        additionalHeaders.add(new BasicHeader("npm-session", generateRandomSession()));

        try {
            final String response = Downloader.getInstance().postBasedFetchContent(nodeAuditUrl.toURI(),
                    packageJson.toString(), ContentType.APPLICATION_JSON, additionalHeaders);
            final JSONObject jsonResponse = new JSONObject(response);
            final NpmAuditParser parser = new NpmAuditParser();
            final List<Advisory> advisories = parser.parse(jsonResponse);
            if (cache != null) {
                cache.put(key, advisories);
            }
            return advisories;
        } catch (RuntimeException | URISyntaxException | JSONException | TooManyRequestsException | ResourceNotFoundException ex) {
            LOGGER.debug("Error connecting to Node Audit API. Error: {}",
                    ex.getMessage());
            throw new SearchException("Could not connect to Node Audit API: " + ex.getMessage(), ex);
        } catch (DownloadFailedException e) {
            if (e.getCause() instanceof HttpResponseException) {
                final HttpResponseException hre = (HttpResponseException) e.getCause();
                switch (hre.getStatusCode()) {
                    case 503:
                        LOGGER.debug("Node Audit API returned `{} {}` - retrying request.",
                                hre.getStatusCode(), hre.getReasonPhrase());
                        if (count < 5) {
                            final int next = count + 1;
                            try {
                                Thread.sleep(1500L * next);
                            } catch (InterruptedException ex) {
                                Thread.currentThread().interrupt();
                                throw new UnexpectedAnalysisException(ex);
                            }
                            return submitPackage(packageJson, key, next);
                        }
                        throw new SearchException("Could not perform Node Audit analysis - service returned a 503.", e);
                    case 400:
                        LOGGER.debug("Invalid payload submitted to Node Audit API. Received response code: {} {}",
                                hre.getStatusCode(), hre.getReasonPhrase());
                        throw new SearchException("Could not perform Node Audit analysis. Invalid payload submitted to Node Audit API.", e);
                    default:
                        LOGGER.debug("Could not connect to Node Audit API. Received response code: {} {}",
                                hre.getStatusCode(), hre.getReasonPhrase());
                        throw new IOException("Could not connect to Node Audit API", e);
                }
            } else {
                LOGGER.debug("Could not connect to Node Audit API. Received generic DownloadException", e);
                throw new IOException("Could not connect to Node Audit API", e);
            }
        }
    }

    /**
     * Generates a random 16 character lower-case hex string.
     *
     * @return a random 16 character lower-case hex string
     */
    private String generateRandomSession() {
        final int length = 16;
        final SecureRandom r = new SecureRandom();
        final StringBuilder sb = new StringBuilder();
        while (sb.length() < length) {
            sb.append(Integer.toHexString(r.nextInt()));
        }
        return sb.substring(0, length);
    }
}
