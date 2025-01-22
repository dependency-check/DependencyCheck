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
 * Copyright (c) 2018 - 2024 Nicolas Henneaux; Hans Aikema. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.artifactory;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.dependency.Dependency;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class ArtifactorySearchResponseHandler implements HttpClientResponseHandler<List<MavenArtifact>> {
    /**
     * Pattern to match the path returned by the Artifactory AQL API.
     */
    private static final Pattern PATH_PATTERN = Pattern.compile("^/(?<groupId>.+)/(?<artifactId>[^/]+)/(?<version>[^/]+)/[^/]+$");

    /**
     * Used for logging.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ArtifactorySearchResponseHandler.class);

    /**
     * Search result reader
     */
    private final ObjectReader fileImplReader;

    /**
     * The dependency that is expected to be in the response from Artifactory (if found)
     */
    private final Dependency expectedDependency;

    /**
     * Creates a responsehandler for the response on a single dependency-search attempt.
     *
     * @param dependency The dependency that is expected to be in the response when found (for validating the FileItem(s) in the response)
     */
    ArtifactorySearchResponseHandler(Dependency dependency) {
        this.fileImplReader = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false).readerFor(FileImpl.class);
        this.expectedDependency = dependency;
    }

    protected boolean init(JsonParser parser) throws IOException {
        com.fasterxml.jackson.core.JsonToken nextToken = parser.nextToken();
        if (nextToken != com.fasterxml.jackson.core.JsonToken.START_OBJECT) {
            throw new IOException("Expected " + com.fasterxml.jackson.core.JsonToken.START_OBJECT + ", got " + nextToken);
        }

        do {
            nextToken = parser.nextToken();
            if (nextToken == null) {
                break;
            }

            if (nextToken.isStructStart()) {
                if (nextToken == com.fasterxml.jackson.core.JsonToken.START_ARRAY && "results".equals(parser.currentName())) {
                    return true;
                } else {
                    parser.skipChildren();
                }
            }
        } while (true);

        return false;
    }

    /**
     * Validates the hashes of the dependency.
     *
     * @param checksums the collection of checksums (md5, sha1, [sha256])
     * @return Whether all available hashes match
     */
    private boolean checkHashes(ChecksumsImpl checksums) {
        final String md5sum = expectedDependency.getMd5sum();
        final String hashMismatchFormat = "Artifact found by API is not matching the {} of the artifact (repository hash is {} while actual is {}) !";
        boolean match = true;
        if (!checksums.getMd5().equals(md5sum)) {
            LOGGER.warn(hashMismatchFormat, "md5", md5sum, checksums.getMd5());
            match = false;
        }
        final String sha1sum = expectedDependency.getSha1sum();
        if (!checksums.getSha1().equals(sha1sum)) {
            LOGGER.warn(hashMismatchFormat, "sha1", sha1sum, checksums.getSha1());
            match = false;
        }
        final String sha256sum = expectedDependency.getSha256sum();
        /* For sha256 we need to validate that the checksum is non-null in the artifactory response.
         * Extract from Artifactory documentation:
         * New artifacts that are uploaded to Artifactory 5.5 and later will automatically have their SHA-256 checksum calculated.
         * However, artifacts that were already hosted in Artifactory before the upgrade will not have their SHA-256 checksum in the database yet.
         * To make full use of Artifactory's SHA-256 capabilities, you need to Migrate the Database to Include SHA-256 making sure that the record
         * for each artifact includes its SHA-256 checksum.
         */
        if (checksums.getSha256() != null && !checksums.getSha256().equals(sha256sum)) {
            LOGGER.warn(hashMismatchFormat, "sha256", sha256sum, checksums.getSha256());
            match = false;
        }
        return match;
    }

    /**
     * Process the Artifactory response.
     *
     * @param response the HTTP response
     * @return a list of the Maven Artifact informations that match the searched dependency hash
     * @throws FileNotFoundException When a matching artifact is not found
     * @throws IOException           thrown if there is an I/O error
     */
    @Override
    public List<MavenArtifact> handleResponse(ClassicHttpResponse response) throws IOException {
        final List<MavenArtifact> result = new ArrayList<>();

        try (InputStreamReader streamReader = new InputStreamReader(response.getEntity().getContent(), StandardCharsets.UTF_8);
             JsonParser parser = fileImplReader.getFactory().createParser(streamReader)) {

            if (init(parser) && parser.nextToken() == JsonToken.START_OBJECT) {
                // at least one result
                do {
                    final FileImpl file = fileImplReader.readValue(parser);

                    if (file.getChecksums() == null) {
                        LOGGER.warn("No checksums found in artifactory search result of uri {}. Please make sure that header X-Result-Detail is retained on any (reverse)-proxy, loadbalancer or WebApplicationFirewall in the network path to your Artifactory Server",
                                file.getUri());
                        continue;
                    }

                    final Optional<Matcher> validationResult = validateUsability(file);
                    if (validationResult.isEmpty()) {
                        continue;
                    }
                    final Matcher pathMatcher = validationResult.get();

                    final String groupId = pathMatcher.group("groupId").replace('/', '.');
                    final String artifactId = pathMatcher.group("artifactId");
                    final String version = pathMatcher.group("version");

                    result.add(new MavenArtifact(groupId, artifactId, version, file.getDownloadUri(),
                            MavenArtifact.derivePomUrl(artifactId, version, file.getDownloadUri())));

                } while (parser.nextToken() == JsonToken.START_OBJECT);
            } else {
                throw new FileNotFoundException("Artifact " + expectedDependency + " not found in Artifactory");
            }
        }
        if (result.isEmpty()) {
            throw new FileNotFoundException("Artifact " + expectedDependency
                    + " not found in Artifactory; discovered sha1 hits not recognized as matching maven artifacts");
        }
        return result;
    }

    /**
     * Validate the FileImpl result for usability as a dependency.
     * <br/>
     * Checks that the actually matches all known hashes and the path appears to match a maven repository G/A/V pattern.
     *
     * @param file The FileImpl from an Artifactory search response
     * @return An Optional with the Matcher for the file path to retrieve the Maven G/A/V coordinates in case result is usable for further
     * processing, otherwise an empty Optional.
     */
    private Optional<Matcher> validateUsability(FileImpl file) {
        final Optional<Matcher> result;
        if (!checkHashes(file.getChecksums())) {
            result = Optional.empty();
        } else {
            final Matcher pathMatcher = PATH_PATTERN.matcher(file.getPath());
            if (!pathMatcher.matches()) {
                LOGGER.debug("Cannot extract the Maven information from the path retrieved in Artifactory {}", file.getPath());
                result = Optional.empty();
            } else {
                result = Optional.of(pathMatcher);
            }
        }
        return result;
    }
}
