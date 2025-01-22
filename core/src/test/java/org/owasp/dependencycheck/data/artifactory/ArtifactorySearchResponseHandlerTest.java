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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.dependency.Dependency;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ArtifactorySearchResponseHandlerTest extends BaseTest {

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
    }

    @Test
    public void shouldProcessCorrectlyArtifactoryAnswerWithoutSha256() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("2e66da15851f9f5b5079228f856c2f090ba98c38");
        dependency.setMd5sum("3dbee72667f107b4f76f2d5aa33c5687");
        final ClassicHttpResponse response = mock(ClassicHttpResponse.class);
        final HttpEntity responseEntity = mock(HttpEntity.class);
        final byte[] payload = ("{\n" +
                "  \"results\" : [ {\n" +
                "    \"repo\" : \"jcenter-cache\",\n" +
                "    \"path\" : \"/com/google/code/gson/gson/2.1/gson-2.1.jar\",\n" +
                "    \"created\" : \"2017-06-14T16:15:37.936+02:00\",\n" +
                "    \"createdBy\" : \"anonymous\",\n" +
                "    \"lastModified\" : \"2012-12-12T22:20:22.000+01:00\",\n" +
                "    \"modifiedBy\" : \"anonymous\",\n" +
                "    \"lastUpdated\" : \"2017-06-14T16:15:37.939+02:00\",\n" +
                "    \"properties\" : {\n" +
                "      \"artifactory.internal.etag\" : [ \"2e66da15851f9f5b5079228f856c2f090ba98c38\" ]\n" +
                "    },\n" +
                "    \"downloadUri\" : \"https://artifactory.techno.ingenico.com/artifactory/jcenter-cache/com/google/code/gson/gson/2.1/gson-2.1.jar\",\n" +
                "    \"remoteUrl\" : \"http://jcenter.bintray.com/com/google/code/gson/gson/2.1/gson-2.1.jar\",\n" +
                "    \"mimeType\" : \"application/java-archive\",\n" +
                "    \"size\" : \"180110\",\n" +
                "    \"checksums\" : {\n" +
                "      \"sha1\" : \"2e66da15851f9f5b5079228f856c2f090ba98c38\",\n" +
                "      \"md5\" : \"3dbee72667f107b4f76f2d5aa33c5687\"\n" +
                "    },\n" +
                "    \"originalChecksums\" : {\n" +
                "      \"sha1\" : \"2e66da15851f9f5b5079228f856c2f090ba98c38\"\n" +
                "    },\n" +
                "    \"uri\" : \"https://artifactory.techno.ingenico.com/artifactory/api/storage/jcenter-cache/com/google/code/gson/gson/2.1/gson-2.1.jar\"\n" +
                "  } ]\n" +
                "}").getBytes(StandardCharsets.UTF_8);
        when(response.getEntity()).thenReturn(responseEntity);
        when(responseEntity.getContent()).thenReturn(new ByteArrayInputStream(payload));


        // When
        final ArtifactorySearchResponseHandler handler = new ArtifactorySearchResponseHandler(dependency);
        final List<MavenArtifact> mavenArtifacts = handler.handleResponse(response);

        // Then

        assertEquals(1, mavenArtifacts.size());
        final MavenArtifact artifact = mavenArtifacts.get(0);
        assertEquals("com.google.code.gson", artifact.getGroupId());
        assertEquals("gson", artifact.getArtifactId());
        assertEquals("2.1", artifact.getVersion());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/jcenter-cache/com/google/code/gson/gson/2.1/gson-2.1.jar",
                artifact.getArtifactUrl());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/jcenter-cache/com/google/code/gson/gson/2.1/gson-2.1.pom",
                artifact.getPomUrl());
    }

    @Test
    public void shouldProcessCorrectlyArtifactoryAnswerWithMultipleMatches() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("94a9ce681a42d0352b3ad22659f67835e560d107");
        dependency.setMd5sum("03dcfdd88502505cc5a805a128bfdd8d");
        final ClassicHttpResponse response = mock(ClassicHttpResponse.class);
        final HttpEntity responseEntity = mock(HttpEntity.class);
        final byte[] payload = multipleMatchesPayload();
        when(response.getEntity()).thenReturn(responseEntity);
        when(responseEntity.getContent()).thenReturn(new ByteArrayInputStream(payload));


        // When
        final ArtifactorySearchResponseHandler handler = new ArtifactorySearchResponseHandler(dependency);
        final List<MavenArtifact> mavenArtifacts = handler.handleResponse(response);

        // Then

        assertEquals(2, mavenArtifacts.size());
        final MavenArtifact artifact1 = mavenArtifacts.get(0);
        assertEquals("axis", artifact1.getGroupId());
        assertEquals("axis", artifact1.getArtifactId());
        assertEquals("1.4", artifact1.getVersion());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/axis/axis/1.4/axis-1.4.jar", artifact1.getArtifactUrl());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/axis/axis/1.4/axis-1.4.pom", artifact1.getPomUrl());
        final MavenArtifact artifact2 = mavenArtifacts.get(1);
        assertEquals("org.apache.axis", artifact2.getGroupId());
        assertEquals("axis", artifact2.getArtifactId());
        assertEquals("1.4", artifact2.getVersion());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/org/apache/axis/axis/1.4/axis-1.4.jar",
                artifact2.getArtifactUrl());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/org/apache/axis/axis/1.4/axis-1.4.pom",
                artifact2.getPomUrl());
    }

    /**
     * Tests the correct working for responses that are sent by Artifactory when the {@code X-Result-Detail} HTTP-Header is missing (e.g. when it
     * gets stripped by an intermediate WebApplicationFirewall configured to only allow a defined subset of HTTP-headers).
     * @throws IOException
     */
    @Test
    public void shouldProcessCorrectlyForMissingXResultDetailHeader() throws IOException {
        // Inject logback ListAppender to capture test-logs from ArtifactorySearchResponseHandler
        final Logger sutLogger = (Logger) LoggerFactory.getLogger(ArtifactorySearchResponseHandler.class);
        final ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
        listAppender.start();
        sutLogger.addAppender(listAppender);

        // Given
        final Dependency dependency = new Dependency();
        dependency.setFileName("freemarker-2.3.33.jar");
        dependency.setSha256sum("ab829182363e747a1530a368436242f4cca7ff309dd29bfca638a1fdc7b6771d");
        dependency.setSha1sum("fecaeb606993fc9fd0f95fe5a644048a69c39474");
        dependency.setMd5sum("4ec135628fd640a201c1d4f8670cc020");
        final ClassicHttpResponse response = mock(ClassicHttpResponse.class);
        final HttpEntity responseEntity = mock(HttpEntity.class);
        final byte[] payload = noXResultDetailHeaderResponse();
        when(response.getEntity()).thenReturn(responseEntity);
        when(responseEntity.getContent()).thenReturn(new ByteArrayInputStream(payload));


        // When
        final ArtifactorySearchResponseHandler handler = new ArtifactorySearchResponseHandler(dependency);
        try {
            handler.handleResponse(response);
            fail("Result with no details due to missing X-Result-Detail header, should throw an exception!");
        } catch (FileNotFoundException e) {
            // Then
            assertEquals("Artifact Dependency{ fileName='freemarker-2.3.33.jar', actualFilePath='null', filePath='null', packagePath='null'} not found in Artifactory; discovered sha1 hits not recognized as matching maven artifacts",
                    e.getMessage());

            // There should be a WARN-log for for each of the results regarding the absence of X-Result-Detail header driven attributes
            final List<ILoggingEvent> logsList = listAppender.list;
            assertEquals("Number of log entries for the ArtifactorySearchResponseHandler", 2, logsList.size());

            ILoggingEvent logEvent = logsList.get(0);
            assertEquals(Level.WARN, logEvent.getLevel());
            assertEquals("No checksums found in artifactory search result of uri {}. Please make sure that header X-Result-Detail is retained on any (reverse)-proxy, loadbalancer or WebApplicationFirewall in the network path to your Artifactory Server", logEvent.getMessage());
            Object[] args = logEvent.getArgumentArray();
            assertEquals(1, args.length);
            assertEquals("https://artifactory.example.com:443/artifactory/api/storage/maven-central-cache/org/freemarker/freemarker/2.3.33/freemarker-2.3.33.jar", args[0]);

            logEvent = logsList.get(1);
            assertEquals(Level.WARN, logEvent.getLevel());
            assertEquals("No checksums found in artifactory search result of uri {}. Please make sure that header X-Result-Detail is retained on any (reverse)-proxy, loadbalancer or WebApplicationFirewall in the network path to your Artifactory Server", logEvent.getMessage());
            args = logEvent.getArgumentArray();
            assertEquals(1, args.length);
            assertEquals("https://artifactory.example.com:443/artifactory/api/storage/gradle-plugins-extended-cache/org/freemarker/freemarker/2.3.33/freemarker-2.3.33.jar", args[0]);

            // Remove our manually injected additional appender
            sutLogger.detachAppender(listAppender);
            listAppender.stop();
        }
    }

    @Test
    public void shouldHandleNoMatches() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("94a9ce681a42d0352b3ad22659f67835e560d108");
        final ClassicHttpResponse response = mock(ClassicHttpResponse.class);
        final HttpEntity responseEntity = mock(HttpEntity.class);
        final byte[] payload = ("{\n" +
                "  \"results\" : [ ]}").getBytes(StandardCharsets.UTF_8);
        when(response.getEntity()).thenReturn(responseEntity);
        when(responseEntity.getContent()).thenReturn(new ByteArrayInputStream(payload));

        // When
        final ArtifactorySearchResponseHandler handler = new ArtifactorySearchResponseHandler(dependency);
        try {
            handler.handleResponse(response);
            fail("No Match found, should throw an exception!");
        } catch (FileNotFoundException e) {
            // Then
            assertEquals("Artifact Dependency{ fileName='null', actualFilePath='null', filePath='null', packagePath='null'} not found in Artifactory",
                    e.getMessage());
        }
    }

    private byte[] multipleMatchesPayload() {
        return ("{\n" +
                "  \"results\" : [ {\n" +
                "    \"repo\" : \"gradle-libs-cache\",\n" +
                "    \"path\" : \"/axis/axis/1.4/axis-1.4.jar\",\n" +
                "    \"created\" : \"2015-07-17T08:58:28.039+02:00\",\n" +
                "    \"createdBy\" : \"loic\",\n" +
                "    \"lastModified\" : \"2006-04-23T06:32:12.000+02:00\",\n" +
                "    \"modifiedBy\" : \"loic\",\n" +
                "    \"lastUpdated\" : \"2015-07-17T08:58:28.049+02:00\",\n" +
                "    \"properties\" : {\n" +
                "    },\n" +
                "    \"downloadUri\" : \"https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/axis/axis/1.4/axis-1.4.jar\",\n" +
                "    \"remoteUrl\" : \"http://gradle.artifactoryonline.com/gradle/libs/axis/axis/1.4/axis-1.4.jar\",\n" +
                "    \"mimeType\" : \"application/java-archive\",\n" +
                "    \"size\" : \"1599570\",\n" +
                "    \"checksums\" : {\n" +
                "      \"sha1\" : \"94a9ce681a42d0352b3ad22659f67835e560d107\",\n" +
                "      \"md5\" : \"03dcfdd88502505cc5a805a128bfdd8d\"\n" +
                "    },\n" +
                "    \"originalChecksums\" : {\n" +
                "      \"sha1\" : \"94a9ce681a42d0352b3ad22659f67835e560d107\",\n" +
                "      \"md5\" : \"03dcfdd88502505cc5a805a128bfdd8d\"\n" +
                "    },\n" +
                "    \"uri\" : \"https://artifactory.techno.ingenico.com/artifactory/api/storage/gradle-libs-cache/axis/axis/1.4/axis-1.4.jar\"\n" +
                "  }, {\n" +
                "    \"repo\" : \"gradle-libs-cache\",\n" +
                "    \"path\" : \"/org/apache/axis/axis/1.4/axis-1.4.jar\",\n" +
                "    \"created\" : \"2015-07-09T10:09:43.074+02:00\",\n" +
                "    \"createdBy\" : \"fabrizio\",\n" +
                "    \"lastModified\" : \"2006-04-23T07:16:56.000+02:00\",\n" +
                "    \"modifiedBy\" : \"fabrizio\",\n" +
                "    \"lastUpdated\" : \"2015-07-09T10:09:43.082+02:00\",\n" +
                "    \"properties\" : {\n" +
                "    },\n" +
                "    \"downloadUri\" : \"https://artifactory.techno.ingenico.com/artifactory/gradle-libs-cache/org/apache/axis/axis/1.4/axis-1.4.jar\",\n" +
                "    \"remoteUrl\" : \"http://gradle.artifactoryonline.com/gradle/libs/org/apache/axis/axis/1.4/axis-1.4.jar\",\n" +
                "    \"mimeType\" : \"application/java-archive\",\n" +
                "    \"size\" : \"1599570\",\n" +
                "    \"checksums\" : {\n" +
                "      \"sha1\" : \"94a9ce681a42d0352b3ad22659f67835e560d107\",\n" +
                "      \"md5\" : \"03dcfdd88502505cc5a805a128bfdd8d\"\n" +
                "    },\n" +
                "    \"originalChecksums\" : {\n" +
                "      \"sha1\" : \"94a9ce681a42d0352b3ad22659f67835e560d107\",\n" +
                "      \"md5\" : \"03dcfdd88502505cc5a805a128bfdd8d\"\n" +
                "    },\n" +
                "    \"uri\" : \"https://artifactory.techno.ingenico.com/artifactory/api/storage/gradle-libs-cache/org/apache/axis/axis/1.4/axis-1.4.jar\"\n" +
                "  } ]}").getBytes(StandardCharsets.UTF_8);
    }

    private byte[] noXResultDetailHeaderResponse() {
        return ("{\n" +
                "  \"results\": [\n" +
                "    {\n" +
                "      \"uri\": \"https://artifactory.example.com:443/artifactory/api/storage/maven-central-cache/org/freemarker/freemarker/2.3.33/freemarker-2.3.33.jar\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"uri\": \"https://artifactory.example.com:443/artifactory/api/storage/gradle-plugins-extended-cache/org/freemarker/freemarker/2.3.33/freemarker-2.3.33.jar\"\n" +
                "    }\n" +
                "  ]\n" +
                "}").getBytes(StandardCharsets.UTF_8);
    }

    @Test
    public void shouldProcessCorrectlyArtifactoryAnswer() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379649");
        final ClassicHttpResponse response = mock(ClassicHttpResponse.class);
        final HttpEntity responseEntity = mock(HttpEntity.class);
        final byte[] payload = payloadWithSha256().getBytes(StandardCharsets.UTF_8);
        when(response.getEntity()).thenReturn(responseEntity);
        when(responseEntity.getContent()).thenReturn(new ByteArrayInputStream(payload));

        // When
        final ArtifactorySearchResponseHandler handler = new ArtifactorySearchResponseHandler(dependency);
        final List<MavenArtifact> mavenArtifacts = handler.handleResponse(response);

        // Then

        assertEquals(1, mavenArtifacts.size());
        final MavenArtifact artifact = mavenArtifacts.get(0);
        assertEquals("com.google.code.gson", artifact.getGroupId());
        assertEquals("gson", artifact.getArtifactId());
        assertEquals("2.8.5", artifact.getVersion());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar",
                artifact.getArtifactUrl());
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5.pom",
                artifact.getPomUrl());
    }

    private String payloadMimicIssue5868() {
        return "{\n" +
                "  \"results\" : [ {\n" +
                "    \"repo\" : \"web-download-cache\",\n" +
                "    \"path\" : \"/download/gson-2.8.5-sources.jar\",\n" +
                "    \"created\" : \"2018-06-20T12:05:23.295+02:00\",\n" +
                "    \"createdBy\" : \"nhenneaux\",\n" +
                "    \"lastModified\" : \"2018-05-22T05:09:01.000+02:00\",\n" +
                "    \"modifiedBy\" : \"nhenneaux\",\n" +
                "    \"lastUpdated\" : \"2018-06-20T12:05:23.302+02:00\",\n" +
                "    \"properties\" : {\n" +
                "      \"artifactory.internal.etag\" : [ \"\\\"2d1dd0fc21ee96bccfab4353d5379649\\\"\" ]\n" +
                "    },\n" +
                "    \"downloadUri\" : \"https://artifactory.techno.ingenico.com/artifactory/web-download-cache/download/gson-2.8.5-sources.jar\",\n" +
                "    \"remoteUrl\" : \"http://example.com/download/gson-2.8.5-sources.jar\",\n" +
                "    \"mimeType\" : \"application/java-archive\",\n" +
                "    \"size\" : \"156280\",\n" +
                "    \"checksums\" : {\n" +
                "      \"sha1\" : \"c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f\",\n" +
                "      \"md5\" : \"2d1dd0fc21ee96bccfab4353d5379649\",\n" +
                "      \"sha256\" : \"512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e\"\n" +
                "    },\n" +
                "    \"originalChecksums\" : {\n" +
                "      \"sha1\" : \"c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f\",\n" +
                "      \"md5\" : \"2d1dd0fc21ee96bccfab4353d5379649\",\n" +
                "      \"sha256\" : \"512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e\"\n" +
                "    },\n" +
                "    \"uri\" : \"https://artifactory.techno.ingenico.com/artifactory/api/storage/web-download-cache/download/gson-2.8.5-sources.jar\"\n" +
                "  },\n" +
                "  {\n" +
                "    \"repo\" : \"repo1-cache\",\n" +
                "    \"path\" : \"/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar\",\n" +
                "    \"created\" : \"2018-06-20T12:05:23.295+02:00\",\n" +
                "    \"createdBy\" : \"nhenneaux\",\n" +
                "    \"lastModified\" : \"2018-05-22T05:09:01.000+02:00\",\n" +
                "    \"modifiedBy\" : \"nhenneaux\",\n" +
                "    \"lastUpdated\" : \"2018-06-20T12:05:23.302+02:00\",\n" +
                "    \"properties\" : {\n" +
                "      \"artifactory.internal.etag\" : [ \"\\\"2d1dd0fc21ee96bccfab4353d5379649\\\"\" ]\n" +
                "    },\n" +
                "    \"downloadUri\" : \"https://artifactory.techno.ingenico.com/artifactory/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar\",\n" +
                "    \"remoteUrl\" : \"http://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar\",\n" +
                "    \"mimeType\" : \"application/java-archive\",\n" +
                "    \"size\" : \"156280\",\n" +
                "    \"checksums\" : {\n" +
                "      \"sha1\" : \"c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f\",\n" +
                "      \"md5\" : \"2d1dd0fc21ee96bccfab4353d5379649\",\n" +
                "      \"sha256\" : \"512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e\"\n" +
                "    },\n" +
                "    \"originalChecksums\" : {\n" +
                "      \"sha1\" : \"c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f\",\n" +
                "      \"md5\" : \"2d1dd0fc21ee96bccfab4353d5379649\",\n" +
                "      \"sha256\" : \"512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e\"\n" +
                "    },\n" +
                "    \"uri\" : \"https://artifactory.techno.ingenico.com/artifactory/api/storage/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar\"\n" +
                "  } ]\n" +
                "}";
    }

    private String payloadWithSha256() {
        return "{\n" +
                "  \"results\" : [ {\n" +
                "    \"repo\" : \"repo1-cache\",\n" +
                "    \"path\" : \"/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar\",\n" +
                "    \"created\" : \"2018-06-20T12:05:23.295+02:00\",\n" +
                "    \"createdBy\" : \"nhenneaux\",\n" +
                "    \"lastModified\" : \"2018-05-22T05:09:01.000+02:00\",\n" +
                "    \"modifiedBy\" : \"nhenneaux\",\n" +
                "    \"lastUpdated\" : \"2018-06-20T12:05:23.302+02:00\",\n" +
                "    \"properties\" : {\n" +
                "      \"artifactory.internal.etag\" : [ \"\\\"2d1dd0fc21ee96bccfab4353d5379649\\\"\" ]\n" +
                "    },\n" +
                "    \"downloadUri\" : \"https://artifactory.techno.ingenico.com/artifactory/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar\",\n" +
                "    \"remoteUrl\" : \"http://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar\",\n" +
                "    \"mimeType\" : \"application/java-archive\",\n" +
                "    \"size\" : \"156280\",\n" +
                "    \"checksums\" : {\n" +
                "      \"sha1\" : \"c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f\",\n" +
                "      \"md5\" : \"2d1dd0fc21ee96bccfab4353d5379649\",\n" +
                "      \"sha256\" : \"512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e\"\n" +
                "    },\n" +
                "    \"originalChecksums\" : {\n" +
                "      \"sha1\" : \"c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f\",\n" +
                "      \"md5\" : \"2d1dd0fc21ee96bccfab4353d5379649\",\n" +
                "      \"sha256\" : \"512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e\"\n" +
                "    },\n" +
                "    \"uri\" : \"https://artifactory.techno.ingenico.com/artifactory/api/storage/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar\"\n" +
                "  } ]\n" +
                "}";
    }

    @Test
    public void shouldProcessCorrectlyArtifactoryAnswerMisMatchMd5() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379640");
        final ClassicHttpResponse response = mock(ClassicHttpResponse.class);
        final HttpEntity responseEntity = mock(HttpEntity.class);
        final byte[] payload = payloadWithSha256().getBytes(StandardCharsets.UTF_8);
        when(response.getEntity()).thenReturn(responseEntity);
        when(responseEntity.getContent()).thenReturn(new ByteArrayInputStream(payload));

        // When
        final ArtifactorySearchResponseHandler handler = new ArtifactorySearchResponseHandler(dependency);
        try {
            handler.handleResponse(response);
            fail("MD5 mismatching should throw an exception!");
        } catch (FileNotFoundException e) {
            // Then
            assertEquals("Artifact " + dependency.toString()
                    + " not found in Artifactory; discovered sha1 hits not recognized as matching maven artifacts", e.getMessage());

        }
    }

    @Test
    public void shouldProcessCorrectlyArtifactoryAnswerMisMatchSha1() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0e");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379649");
        final ClassicHttpResponse response = mock(ClassicHttpResponse.class);
        final HttpEntity responseEntity = mock(HttpEntity.class);
        final byte[] payload = payloadWithSha256().getBytes(StandardCharsets.UTF_8);
        when(response.getEntity()).thenReturn(responseEntity);
        when(responseEntity.getContent()).thenReturn(new ByteArrayInputStream(payload));

        // When
        final ArtifactorySearchResponseHandler handler = new ArtifactorySearchResponseHandler(dependency);
        try {
            handler.handleResponse(response);
            fail("SHA1 mismatching should throw an exception!");
        } catch (FileNotFoundException e) {
            // Then
            assertEquals("Artifact Dependency{ fileName='null', actualFilePath='null', filePath='null', packagePath='null'} not found in Artifactory; discovered sha1 hits not recognized as matching maven artifacts", e.getMessage());
        }
    }

    @Test
    public void shouldProcessCorrectlyArtifactoryAnswerMisMatchSha256() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068f");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379649");
        final ClassicHttpResponse response = mock(ClassicHttpResponse.class);
        final HttpEntity responseEntity = mock(HttpEntity.class);
        final byte[] payload = payloadWithSha256().getBytes(StandardCharsets.UTF_8);
        when(response.getEntity()).thenReturn(responseEntity);
        when(responseEntity.getContent()).thenReturn(new ByteArrayInputStream(payload));

        // When
        final ArtifactorySearchResponseHandler handler = new ArtifactorySearchResponseHandler(dependency);
        try {
            handler.handleResponse(response);
            fail("SHA256 mismatching should throw an exception!");
        } catch (FileNotFoundException e) {
            // Then
            assertEquals("Artifact Dependency{ fileName='null', actualFilePath='null', filePath='null', packagePath='null'} not found in Artifactory; discovered sha1 hits not recognized as matching maven artifacts", e.getMessage());
        }
    }

    @Test
    public void shouldThrowNotFoundWhenPatternCannotBeParsed() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379649");
        final ClassicHttpResponse response = mock(ClassicHttpResponse.class);
        final HttpEntity responseEntity = mock(HttpEntity.class);
        final byte[] payload = payloadWithSha256().replace("/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar", "/2.8.5/gson-2.8.5-sources.jar")
                .getBytes(StandardCharsets.UTF_8);
        when(response.getEntity()).thenReturn(responseEntity);
        when(responseEntity.getContent()).thenReturn(new ByteArrayInputStream(payload));

        // When
        final ArtifactorySearchResponseHandler handler = new ArtifactorySearchResponseHandler(dependency);
        try {
            handler.handleResponse(response);
            fail("Maven GAV pattern mismatch for filepath should throw a not found exception!");
        } catch (FileNotFoundException e) {
            // Then
            assertEquals("Artifact Dependency{ fileName='null', actualFilePath='null', filePath='null', packagePath='null'} not found in Artifactory; discovered sha1 hits not recognized as matching maven artifacts", e.getMessage());
        }
    }

    @Test
    public void shouldSkipResultsWherePatternCannotBeParsed() throws IOException {
        // Given
        Dependency dependency = new Dependency();
        dependency.setSha1sum("c5b4c491aecb72e7c32a78da0b5c6b9cda8dee0f");
        dependency.setSha256sum("512b4bf6927f4864acc419b8c5109c23361c30ed1f5798170248d33040de068e");
        dependency.setMd5sum("2d1dd0fc21ee96bccfab4353d5379649");
        final ClassicHttpResponse response = mock(ClassicHttpResponse.class);
        final HttpEntity responseEntity = mock(HttpEntity.class);
        final byte[] payload = payloadMimicIssue5868().getBytes(StandardCharsets.UTF_8);
        when(response.getEntity()).thenReturn(responseEntity);
        when(responseEntity.getContent()).thenReturn(new ByteArrayInputStream(payload));

        // When
        final ArtifactorySearchResponseHandler handler = new ArtifactorySearchResponseHandler(dependency);
        List<MavenArtifact> result = handler.handleResponse(response);
        // Then
        assertEquals(1, result.size());
        MavenArtifact artifact = result.get(0);
        assertEquals("com.google.code.gson", artifact.getGroupId());
        assertEquals("gson", artifact.getArtifactId());
        assertEquals("2.8.5", artifact.getVersion());
    }
}
