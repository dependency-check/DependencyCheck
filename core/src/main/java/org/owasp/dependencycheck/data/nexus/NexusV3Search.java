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
 * Copyright (c) 2023 Hans Aikema. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nexus;

import org.apache.hc.client5.http.HttpResponseException;
import org.apache.hc.client5.http.impl.classic.AbstractHttpClientResponseHandler;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.message.BasicHeader;
import org.jetbrains.annotations.Nullable;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Class of methods to search Nexus v3 repositories.
 *
 * @author Hans Aikema
 */
@ThreadSafe
public class NexusV3Search implements NexusSearch {

    /**
     * By default, NexusV3Search accepts only classifier-less artifacts.
     * <p>
     * This prevents, among others, sha1-collisions for empty jars on empty javadoc/sources jars.
     * See e.g. issues #5559 and #5118
     */
    private final Set<String> acceptedClassifiers = new HashSet<>();

    /**
     * The root URL for the Nexus repository service.
     */
    private final URL rootURL;

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
    private static final Logger LOGGER = LoggerFactory.getLogger(NexusV3Search.class);

    /**
     * Creates a NexusV3Search for the given repository URL.
     *
     * @param settings the configured settings
     * @param useProxy flag indicating if the proxy settings should be used
     * @throws MalformedURLException thrown if the configured URL is
     *                               invalid
     */
    public NexusV3Search(Settings settings, boolean useProxy) throws MalformedURLException {
        this.settings = settings;
        this.useProxy = useProxy;
        this.acceptedClassifiers.add(null);
        final String searchUrl = settings.getString(Settings.KEYS.ANALYZER_NEXUS_URL);
        LOGGER.debug("Nexus Search URL: {}", searchUrl);
        this.rootURL = new URL(searchUrl);

    }

    @Override
    public MavenArtifact searchSha1(String sha1) throws IOException {
        if (null == sha1 || !sha1.matches("^[0-9A-Fa-f]{40}$")) {
            throw new IllegalArgumentException("Invalid SHA1 format");
        }

        final List<MavenArtifact> collectedMatchingArtifacts = new ArrayList<>(1);
        try (CloseableHttpClient client = Downloader.getInstance().getHttpClient(useProxy)) {
            String continuationToken = retrievePageAndAddMatchingArtifact(client, collectedMatchingArtifacts, sha1, null);
            while (continuationToken != null && collectedMatchingArtifacts.isEmpty()) {
                continuationToken = retrievePageAndAddMatchingArtifact(client, collectedMatchingArtifacts, sha1, continuationToken);
            }
        }
        if (collectedMatchingArtifacts.isEmpty()) {
            throw new FileNotFoundException("Artifact not found in Nexus");
        } else {
            return collectedMatchingArtifacts.get(0);
        }
    }

    private String retrievePageAndAddMatchingArtifact(CloseableHttpClient client, List<MavenArtifact> collectedMatchingArtifacts, String sha1,
                                                      @Nullable String continuationToken) throws IOException {
        final URL url;
        LOGGER.debug("Search with continuation token {}", continuationToken);
        if (continuationToken == null) {
            url = new URL(rootURL, String.format("v1/search/?sha1=%s",
                    sha1.toLowerCase()));
        } else {
            url = new URL(rootURL, String.format("v1/search/?sha1=%s&continuationToken=%s",
                    sha1.toLowerCase(), continuationToken));
        }

        LOGGER.debug("Searching Nexus url {}", url);
        // Determine if we need to use a proxy. The rules:
        // 1) If the proxy is set, AND the setting is set to true, use the proxy
        // 2) Otherwise, don't use the proxy (either the proxy isn't configured,
        // or proxy is specifically set to false
        final NexusV3SearchResponseHandler handler = new NexusV3SearchResponseHandler(collectedMatchingArtifacts, sha1, acceptedClassifiers);
        try {
            return Downloader.getInstance().fetchAndHandle(client, url, handler, List.of(new BasicHeader(HttpHeaders.ACCEPT,
                            ContentType.APPLICATION_JSON)));
        } catch (TooManyRequestsException | ResourceNotFoundException | DownloadFailedException e) {
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
            throw new IOException("Could not connect to Nexus", e);
        }
    }

    private static final class NexusV3SearchResponseHandler extends AbstractHttpClientResponseHandler<String> {

        /**
         * The list to which matching artifacts are to be added
         */
        private final List<MavenArtifact> matchingArtifacts;
        /**
         * The sha1 for which the search results are being handled
         */
        private final String sha1;
        /**
         * The classifiers to be accepted
         */
        private final Set<String> acceptedClassifiers;

        private NexusV3SearchResponseHandler(List<MavenArtifact> matchingArtifacts, String sha1, Set<String> acceptedClassifiers) {
            this.matchingArtifacts = matchingArtifacts;
            this.sha1 = sha1;
            this.acceptedClassifiers = acceptedClassifiers;
        }

        @Override
        public @Nullable String handleEntity(HttpEntity entity) throws IOException {
            try (InputStream in = entity.getContent();
                 InputStreamReader isReader = new InputStreamReader(in, StandardCharsets.UTF_8);
                 BufferedReader reader = new BufferedReader(isReader);
            ) {
                final String jsonString = reader.lines().collect(Collectors.joining("\n"));
                LOGGER.debug("JSON String was >>>{}<<<", jsonString);
                final JsonObject jsonResponse;
                try (
                        StringReader stringReader = new StringReader(jsonString);
                        JsonReader jsonReader = Json.createReader(stringReader)
                ) {
                    jsonResponse = jsonReader.readObject();
                }
                LOGGER.debug("Response: {}", jsonResponse);
                final JsonArray components = jsonResponse.getJsonArray("items");
                LOGGER.debug("Items: {}", components);
                final String continuationToken = jsonResponse.getString("continuationToken", null);
                boolean found = false;
                for (int i = 0; i < components.size() && !found; i++) {
                    boolean jarFound = false;
                    boolean pomFound = false;
                    String downloadUrl = null;
                    String groupId = null;
                    String artifactId = null;
                    String version = null;
                    String pomUrl = null;

                    final JsonObject component = components.getJsonObject(i);

                    final String format = component.getString("format", "unknown");
                    if ("maven2".equals(format)) {
                        LOGGER.debug("Checking Maven2 artifact for {}", component);
                        final JsonArray assets = component.getJsonArray("assets");
                        for (int j = 0; !found && j < assets.size(); j++) {
                            final JsonObject asset = assets.getJsonObject(j);
                            LOGGER.debug("Checking {}", asset);
                            final JsonObject checksums = asset.getJsonObject("checksum");
                            final JsonObject maven2 = asset.getJsonObject("maven2");
                            if (maven2 != null) {
                                // logical names for the jar acceptance routine
                                final boolean shaMatch = checksums != null && sha1.equals(checksums.getString("sha1", null));
                                final boolean hasAcceptedClassifier = acceptedClassifiers.contains(maven2.getString("classifier", null));
                                final boolean isAJar = "jar".equals(maven2.getString("extension", null));
                                LOGGER.debug("shaMatch {}", shaMatch);
                                LOGGER.debug("hasAcceptedClassifier {}", hasAcceptedClassifier);
                                LOGGER.debug("isAJar {}", isAJar);
                                if (
                                        isAJar
                                        && hasAcceptedClassifier
                                        && shaMatch
                                ) {
                                    downloadUrl = asset.getString("downloadUrl");
                                    groupId = maven2.getString("groupId");
                                    artifactId = maven2.getString("artifactId");
                                    version = maven2.getString("version");

                                    jarFound = true;
                                } else if ("pom".equals(maven2.getString("extension"))) {
                                    LOGGER.debug("pom found {}", asset);
                                    pomFound = true;
                                    pomUrl = asset.getString("downloadUrl");
                                }
                            }
                            if (pomFound && jarFound) {
                                found = true;
                            }
                        }
                        if (found) {
                            matchingArtifacts.add(new MavenArtifact(groupId, artifactId, version, downloadUrl, pomUrl));
                        } else if (jarFound) {
                            final MavenArtifact ma = new MavenArtifact(groupId, artifactId, version, downloadUrl);
                            ma.setPomUrl(MavenArtifact.derivePomUrl(artifactId, version, downloadUrl));
                            matchingArtifacts.add(ma);
                            found = true;
                        }
                    }
                }
                return continuationToken;
            }
        }
    }

    @Override
    public boolean preflightRequest() {
        try {
            final URL url = new URL(rootURL, "v1/status");
            final String response = Downloader.getInstance().fetchContent(url, useProxy, StandardCharsets.UTF_8);
            if (response == null || !response.isEmpty()) {
                LOGGER.warn("Expected empty OK response (content-length 0), got {}", response == null ? "null" : response.length());
                return false;
            }
        } catch (IOException | TooManyRequestsException | ResourceNotFoundException e) {
            LOGGER.warn("Pre-flight request to Nexus failed: ", e);
            return false;
        }
        return true;
    }

}
