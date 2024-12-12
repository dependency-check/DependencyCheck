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
package org.owasp.dependencycheck.data.central;

import org.apache.hc.client5.http.impl.classic.AbstractHttpClientResponseHandler;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.concurrent.ThreadSafe;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.apache.commons.jcs3.access.exception.CacheException;
import org.owasp.dependencycheck.data.cache.DataCache;
import org.owasp.dependencycheck.data.cache.DataCacheFactory;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.XmlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Class of methods to search Maven Central via Central.
 *
 * @author colezlaw
 */
@ThreadSafe
public class CentralSearch {

    /**
     * The URL for the Central service.
     */
    private final String rootURL;

    /**
     * The Central Search Query.
     */
    private final String query;

    /**
     * Whether to use the Proxy when making requests.
     */
    private final boolean useProxy;

    /**
     * Used for logging.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CentralSearch.class);
    /**
     * The configured settings.
     */
    private final Settings settings;
    /**
     * Persisted disk cache for `npm audit` results.
     */
    private DataCache<List<MavenArtifact>> cache;

    /**
     * Creates a NexusSearch for the given repository URL.
     *
     * @param settings the configured settings
     * @throws MalformedURLException thrown if the configured URL is invalid
     */
    public CentralSearch(Settings settings) throws MalformedURLException {
        this.settings = settings;

        final String searchUrl = settings.getString(Settings.KEYS.ANALYZER_CENTRAL_URL);
        LOGGER.debug("Central Search URL: {}", searchUrl);
        if (isInvalidURL(searchUrl)) {
            throw new MalformedURLException(String.format("The configured central analyzer URL is invalid: %s", searchUrl));
        }
        this.rootURL = searchUrl;
        final String queryStr = settings.getString(Settings.KEYS.ANALYZER_CENTRAL_QUERY);
        LOGGER.debug("Central Search Query: {}", queryStr);
        if (!queryStr.matches("^%s.*%s.*$")) {
            final String msg = String.format("The configured central analyzer query parameter is invalid (it must have two %%s): %s", queryStr);
            throw new MalformedURLException(msg);
        }
        this.query = queryStr;
        LOGGER.debug("Central Search Full URL: {}", String.format(query, rootURL, "[SHA1]"));
        if (null != settings.getString(Settings.KEYS.PROXY_SERVER) || null != System.getProperty("https.proxyHost")) {
            useProxy = true;
            LOGGER.debug("Using proxy");
        } else {
            useProxy = false;
            LOGGER.debug("Not using proxy");
        }
        if (settings.getBoolean(Settings.KEYS.ANALYZER_CENTRAL_USE_CACHE, true)) {
            try {
                final DataCacheFactory factory = new DataCacheFactory(settings);
                cache = factory.getCentralCache();
            } catch (CacheException ex) {
                settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_USE_CACHE, false);
                LOGGER.debug("Error creating cache, disabling caching", ex);
            }
        }
    }

    /**
     * Searches the configured Central URL for the given SHA1 hash. If the
     * artifact is found, a <code>MavenArtifact</code> is populated with the
     * GAV.
     *
     * @param sha1 the SHA-1 hash string for which to search
     * @return the populated Maven GAV.
     * @throws FileNotFoundException if the specified artifact is not found
     * @throws IOException if it's unable to connect to the specified repository
     * @throws TooManyRequestsException if Central has received too many
     * requests.
     */
    public List<MavenArtifact> searchSha1(String sha1) throws IOException, TooManyRequestsException {
        if (null == sha1 || !sha1.matches("^[0-9A-Fa-f]{40}$")) {
            throw new IllegalArgumentException("Invalid SHA1 format");
        }
        if (cache != null) {
            final List<MavenArtifact> cached = cache.get(sha1);
            if (cached != null && !cached.isEmpty()) {
                LOGGER.debug("cache hit for Central: " + sha1);
                return cached;
            }
        }
        final List<MavenArtifact> result = new ArrayList<>();
        final URL url = new URL(String.format(query, rootURL, sha1));

        LOGGER.trace("Searching Central url {}", url);

        // JSON would be more elegant, but there's not currently a dependency
        // on JSON, so don't want to add one just for this
        final BasicHeader acceptHeader = new BasicHeader("Accept", "application/xml");
        final AbstractHttpClientResponseHandler<Document> handler = new AbstractHttpClientResponseHandler<>() {
            @Override
            public Document handleEntity(HttpEntity entity) throws IOException {
                try (InputStream in = entity.getContent()) {
                    final DocumentBuilder builder = XmlUtils.buildSecureDocumentBuilder();
                    return builder.parse(in);
                } catch (ParserConfigurationException | SAXException | IOException e) {
                    // Anything else is jacked up XML stuff that we really can't recover from well
                    final String errorMessage = "Failed to parse MavenCentral XML Response: " + e.getMessage();
                    throw new IOException(errorMessage, e);
                }
            }
        };
        try {
            final Document doc = Downloader.getInstance().fetchAndHandle(url, handler, List.of(acceptHeader), useProxy);
            if (doc == null) {
                return new ArrayList<>();
            }
            final boolean missing = addMavenArtifacts(doc, result);

            if (missing) {
                if (cache != null) {
                    cache.put(sha1, result);
                }
                throw new FileNotFoundException("Artifact not found in Central");
            }
        } catch (XPathExpressionException e) {
            final String errorMessage = "Failed to parse MavenCentral XML Response: " + e.getMessage();
            throw new IOException(errorMessage, e);
        } catch (TooManyRequestsException e) {
            final String errorMessage = "Too many requests sent to MavenCentral; additional requests are being rejected.";
            throw new TooManyRequestsException(errorMessage, e);
        } catch (ResourceNotFoundException | DownloadFailedException e) {
            final String errorMessage = "Could not connect to MavenCentral " + e.getMessage();
            throw new IOException(errorMessage, e);
        }
        if (cache != null) {
            cache.put(sha1, result);
        }
        return result;
    }

    /**
     * Collect the artifacts from a MavenCentral search result and add them to the list.
     * @param doc The Document received in response to the SHA1 search-request
     * @param result The list of MavenArtifacts to which found artifacts will be added
     * @return Whether the given document holds no search results
     */
    private boolean addMavenArtifacts(Document doc, List<MavenArtifact> result) throws XPathExpressionException {
        boolean missing = false;
        final XPath xpath = XPathFactory.newInstance().newXPath();
        final String numFound = xpath.evaluate("/SolrWrappedResponse/response/numFound", doc);
        if ("0".equals(numFound)) {
            missing = true;
        } else {
            final NodeList docs = (NodeList) xpath.evaluate("/SolrWrappedResponse/response/docs/docs", doc, XPathConstants.NODESET);
            for (int i = 0; i < docs.getLength(); i++) {
                final String g = xpath.evaluate("./g", docs.item(i));
                LOGGER.trace("GroupId: {}", g);
                final String a = xpath.evaluate("./a", docs.item(i));
                LOGGER.trace("ArtifactId: {}", a);
                final String v = xpath.evaluate("./v", docs.item(i));
                final NodeList attributes = (NodeList) xpath.evaluate("./arr[@name='ec']/str", docs.item(i), XPathConstants.NODESET);
                boolean pomAvailable = false;
                boolean jarAvailable = false;
                for (int x = 0; x < attributes.getLength(); x++) {
                    final String tmp = xpath.evaluate(".", attributes.item(x));
                    if (".pom".equals(tmp)) {
                        pomAvailable = true;
                    } else if (".jar".equals(tmp)) {
                        jarAvailable = true;
                    }
                }
                final String centralContentUrl = settings.getString(Settings.KEYS.CENTRAL_CONTENT_URL);
                String artifactUrl = null;
                String pomUrl = null;
                if (jarAvailable) {
                    //org/springframework/spring-core/3.2.0.RELEASE/spring-core-3.2.0.RELEASE.pom
                    artifactUrl = centralContentUrl + g.replace('.', '/') + '/' + a + '/'
                            + v + '/' + a + '-' + v + ".jar";
                }
                if (pomAvailable) {
                    //org/springframework/spring-core/3.2.0.RELEASE/spring-core-3.2.0.RELEASE.pom
                    pomUrl = centralContentUrl + g.replace('.', '/') + '/' + a + '/'
                            + v + '/' + a + '-' + v + ".pom";
                }
                result.add(new MavenArtifact(g, a, v, artifactUrl, pomUrl));
            }
        }
        return missing;
    }

    /**
     * Tests to determine if the given URL is <b>invalid</b>.
     *
     * @param url the URL to evaluate
     * @return true if the URL is malformed; otherwise false
     */
    private boolean isInvalidURL(String url) {
        try {
            final URL u = new URL(url);
            u.toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            LOGGER.trace("URL is invalid: {}", url);
            return true;
        }
        return false;
    }
}
