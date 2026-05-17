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
package org.owasp.dependencycheck.data.nexus;

import org.apache.hc.client5.http.HttpResponseException;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.message.BasicHeader;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.ForbiddenException;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.ToXMLDocumentResponseHandler;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.annotation.concurrent.ThreadSafe;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

/**
 * Class of methods to search Nexus repositories.
 *
 * @author colezlaw
 * @deprecated Nexus v2 was EOL on 30 June 2025. Migration to Nexus v3 is required.
 */
@SuppressWarnings({"DeprecatedIsStillUsed", "unused"})
@Deprecated(forRemoval = true, since = "v12.2.2")
@ThreadSafe
public class NexusV2Search implements NexusSearch {

    /**
     * The root URL for the Nexus repository service.
     */
    private final URL rootURL;

    /**
     * Used for logging.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NexusV2Search.class);

    /**
     * Creates a NexusSearch for the given repository URL.
     *
     * @param settings the configured settings
     * @param useProxy flag indicating if the proxy settings should be used
     * @throws java.net.MalformedURLException thrown if the configured URL is
     * invalid
     */
    public NexusV2Search(Settings settings, boolean useProxy) throws MalformedURLException {
        final String searchUrl = settings.getString(Settings.KEYS.ANALYZER_NEXUS_URL);
        LOGGER.debug("Nexus Search URL: {}", searchUrl);
        this.rootURL = new URL(searchUrl);
    }

    @Override
    public MavenArtifact searchSha1(String sha1) throws IOException {
        if (null == sha1 || !sha1.matches("^[0-9A-Fa-f]{40}$")) {
            throw new IllegalArgumentException("Invalid SHA1 format");
        }

        final URL url = new URL(rootURL, String.format("identify/sha1/%s",
                sha1.toLowerCase()));

        LOGGER.debug("Searching Nexus url {}", url);

        try {
            // JSON would be more elegant, but there's not currently a dependency
            // on JSON, so don't want to add one just for this
            final ToXMLDocumentResponseHandler handler = new ToXMLDocumentResponseHandler();
            final Document doc = Downloader.getInstance().fetchAndHandle(url, handler, List.of(new BasicHeader(HttpHeaders.ACCEPT,
                    ContentType.APPLICATION_XML)));
            final XPath xpath = XPathFactory.newInstance().newXPath();
            final String groupId = xpath
                    .evaluate(
                            "/org.sonatype.nexus.rest.model.NexusArtifact/groupId",
                            doc);
            final String artifactId = xpath.evaluate(
                    "/org.sonatype.nexus.rest.model.NexusArtifact/artifactId",
                    doc);
            final String version = xpath
                    .evaluate(
                            "/org.sonatype.nexus.rest.model.NexusArtifact/version",
                            doc);
            final String link = xpath
                    .evaluate(
                            "/org.sonatype.nexus.rest.model.NexusArtifact/artifactLink",
                            doc);
            final String pomLink = xpath
                    .evaluate(
                            "/org.sonatype.nexus.rest.model.NexusArtifact/pomLink",
                            doc);
            final MavenArtifact ma = new MavenArtifact(groupId, artifactId, version);
            if (link != null && !link.isEmpty()) {
                ma.setArtifactUrl(link);
            }
            if (pomLink != null && !pomLink.isEmpty()) {
                ma.setPomUrl(pomLink);
            }
            return ma;
        } catch (DownloadFailedException | TooManyRequestsException e) {
                if (LOGGER.isDebugEnabled()) {
                    int responseCode = -1;
                    String responseMessage = "";
                    if (e.getCause() instanceof HttpResponseException) {
                        final HttpResponseException cause = (HttpResponseException) e.getCause();
                        responseCode = cause.getStatusCode();
                        responseMessage = cause.getReasonPhrase();
                    }
                    LOGGER.debug("Could not connect to Nexus received response code: {} {}",
                            responseCode, responseMessage);
                }
                throw new IOException("Could not connect to Nexus");
        } catch (ResourceNotFoundException e) {
            throw new FileNotFoundException("Artifact not found in Nexus");
        } catch (XPathExpressionException | URISyntaxException | ForbiddenException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    @Override
    public boolean preflightRequest() {
        try {
            final URL url = new URL(rootURL, "status");
            final ToXMLDocumentResponseHandler handler = new ToXMLDocumentResponseHandler();
            final Document doc = Downloader.getInstance().fetchAndHandle(url, handler, List.of(new BasicHeader(HttpHeaders.ACCEPT,
                    ContentType.APPLICATION_XML)));
            if (!"status".equals(doc.getDocumentElement().getNodeName())) {
                LOGGER.warn("Pre-flight request to Nexus failed; expected root node name of status, got {}", doc.getDocumentElement().getNodeName());
                return false;
            }
        } catch (IOException | TooManyRequestsException | ResourceNotFoundException | URISyntaxException e) {
            LOGGER.warn("Pre-flight request to Nexus failed: ", e);
            return false;
        }
        return true;
    }

}
