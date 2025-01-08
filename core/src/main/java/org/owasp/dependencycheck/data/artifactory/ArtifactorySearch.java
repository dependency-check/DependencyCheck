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
 * Copyright (c) 2018 Nicolas Henneaux. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.artifactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import javax.annotation.concurrent.ThreadSafe;

import org.apache.hc.core5.http.message.BasicHeader;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Class of methods to search Artifactory for hashes and determine Maven GAV
 * from there.
 *
 * Data classes copied from JFrog's artifactory-client-java project.
 *
 * @author nhenneaux
 */
@ThreadSafe
public class ArtifactorySearch {

    /**
     * Used for logging.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ArtifactorySearch.class);

    /**
     * The URL for the Central service.
     */
    private final String rootURL;

    /**
     * Whether to use the Proxy when making requests.
     */
    private final boolean allowUsingProxy;


    /**
     * Creates a ArtifactorySearch for the given repository URL.
     *
     * @param settings the configured settings
     */
    public ArtifactorySearch(Settings settings) {

        final String searchUrl = settings.getString(Settings.KEYS.ANALYZER_ARTIFACTORY_URL);

        this.rootURL = searchUrl;
        LOGGER.debug("Artifactory Search URL {}", searchUrl);

        if (null != settings.getString(Settings.KEYS.PROXY_SERVER)) {
            this.allowUsingProxy = settings.getBoolean(Settings.KEYS.ANALYZER_ARTIFACTORY_USES_PROXY, false);
            LOGGER.debug("Using proxy configuration? {}", allowUsingProxy);
        } else {
            this.allowUsingProxy = settings.getBoolean(Settings.KEYS.ANALYZER_ARTIFACTORY_USES_PROXY, true);
            LOGGER.debug("Using default non-legacy proxy configuration");
        }

    }

    /**
     * Searches the configured Central URL for the given hash (MD5, SHA1 and
     * SHA256). If the artifact is found, a <code>MavenArtifact</code> is
     * populated with the GAV.
     *
     * @param dependency the dependency for which to search (search is based on
     * hashes)
     * @return the populated Maven GAV.
     * @throws FileNotFoundException if the specified artifact is not found
     * @throws IOException if it's unable to connect to the specified repository
     */
    public List<MavenArtifact> search(Dependency dependency) throws IOException {

        final String sha1sum = dependency.getSha1sum();
        final URL url = buildUrl(sha1sum);
        final StringBuilder msg = new StringBuilder("Could not connect to Artifactory at")
                .append(url);
        try {
            final BasicHeader artifactoryResultDetail = new BasicHeader("X-Result-Detail", "info");
            return Downloader.getInstance().fetchAndHandle(url, new ArtifactorySearchResponseHandler(dependency), List.of(artifactoryResultDetail),
                    allowUsingProxy);
        } catch (TooManyRequestsException e) {
            throw new IOException(msg.append(" (429): Too manu requests").toString(), e);
        } catch (URISyntaxException e) {
            throw new IOException(msg.append(" (400): Invalid URL").toString(), e);
        } catch (ResourceNotFoundException e) {
            throw new IOException(msg.append(" (404): Not found").toString(), e);
        }
    }

    /**
     * Constructs the URL using the SHA1 checksum.
     *
     * @param sha1sum the SHA1 checksum
     * @return the API URL to search for the given checksum
     * @throws MalformedURLException thrown if the URL is malformed
     */
    private URL buildUrl(String sha1sum) throws MalformedURLException {
        // TODO Investigate why sha256 parameter is not working
        // API defined https://www.jfrog.com/confluence/display/RTF/Artifactory+REST+API#ArtifactoryRESTAPI-ChecksumSearch
        return new URL(rootURL + "/api/search/checksum?sha1=" + sha1sum);
    }

    /**
     * Performs a pre-flight request to ensure the Artifactory service is
     * reachable.
     *
     * @return <code>true</code> if Artifactory could be reached; otherwise
     * <code>false</code>.
     */
    public boolean preflightRequest() {
        URL url = null;
        try {
            url = buildUrl(Checksum.getSHA1Checksum(UUID.randomUUID().toString()));
            Downloader.getInstance().fetchContent(url, StandardCharsets.UTF_8);
            return true;
        } catch (IOException e) {
            LOGGER.error("Cannot connect to Artifactory", e);
            return false;
        } catch (TooManyRequestsException e) {
            LOGGER.warn("Expected 200 result from Artifactory ({}), got 429", url);
            return false;
        } catch (ResourceNotFoundException e) {
            LOGGER.warn("Expected 200 result from Artifactory ({}), got 404", url);
            return false;
        }

    }
}
