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
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.Settings;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.everyItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.owasp.dependencycheck.data.update.NvdApiDataSource.FeedUrl.DEFAULT_FILE_PATTERN;
import static org.owasp.dependencycheck.data.update.NvdApiDataSource.FeedUrl.extractFromUrlOptionalPattern;
import static org.owasp.dependencycheck.data.update.NvdApiDataSource.FeedUrl.isMandatoryFeedYear;

class NvdApiDataSourceTest {

    @Nested
    class FeedUrlParsing {

        @Test
        void shouldExtractUrlWithPattern() throws Exception {
            String nvdDataFeedUrl = "https://internal.server/nist/nvdcve-{0}.json.gz";
            String expectedUrl = "https://internal.server/nist/nvdcve-2045.json.gz";
            NvdApiDataSource.FeedUrl result = extractFromUrlOptionalPattern(nvdDataFeedUrl);

            assertEquals(expectedUrl, result.toFormattedUrlString("2045"));
            assertEquals(URI.create(expectedUrl).toURL(), result.toFormattedUrl("2045"));
            assertEquals(URI.create("https://internal.server/nist/some-file.txt").toURL(), result.toSuffixedUrl("some-file.txt"));

            assertEquals(expectedUrl, result.toFormattedUrlString("2045"));
            assertEquals(URI.create(expectedUrl).toURL(), result.toFormattedUrl("2045"));
        }

        @Test
        void shouldAllowTransformingFilePattern() {
            NvdApiDataSource.FeedUrl result = extractFromUrlOptionalPattern("https://internal.server/nist/nvdcve-{0}.json.gz")
                    .withPattern(p -> p.orElseThrow().replace(".json.gz", ".something"));
            assertEquals("https://internal.server/nist/nvdcve-ok.something", result.toFormattedUrlString("ok"));

            NvdApiDataSource.FeedUrl resultNoPattern = extractFromUrlOptionalPattern("https://internal.server/nist/")
                    .withPattern(p -> p.orElse("my-suffix-{0}.json.gz"));
            assertEquals("https://internal.server/nist/my-suffix-ok.json.gz", resultNoPattern.toFormattedUrlString("ok"));
        }

        @Test
        void shouldExtractUrlWithoutPattern() throws Exception {
            String nvdDataFeedUrl = "https://internal.server/nist/";
            NvdApiDataSource.FeedUrl result = extractFromUrlOptionalPattern(nvdDataFeedUrl);

            assertThrows(NoSuchElementException.class, () -> result.toFormattedUrlString("2045"));
            assertThrows(NoSuchElementException.class, () -> result.toFormattedUrl("2045"));
            assertEquals(URI.create("https://internal.server/nist/some-file.txt").toURL(), result.toSuffixedUrl("some-file.txt"));

            String expectedUrl = "https://internal.server/nist/nvdcve-2045.json.gz";
            NvdApiDataSource.FeedUrl resultWithPattern = extractFromUrlOptionalPattern(nvdDataFeedUrl)
                    .withPattern(p -> p.orElse(DEFAULT_FILE_PATTERN));

            assertEquals(expectedUrl, resultWithPattern.toFormattedUrlString("2045"));
            assertEquals(URI.create(expectedUrl).toURL(), resultWithPattern.toFormattedUrl("2045"));
        }

        @Test
        void extractUrlWithoutPatternShouldAddTrailingSlashes() {
            String nvdDataFeedUrl = "https://internal.server/nist";
            String expectedUrl = "https://internal.server/nist/nvdcve-2045.json.gz";

            NvdApiDataSource.FeedUrl result = extractFromUrlOptionalPattern(nvdDataFeedUrl)
                    .withPattern(p -> p.orElse(DEFAULT_FILE_PATTERN));

            assertEquals(expectedUrl, result.toFormattedUrlString("2045"));
        }
    }

    @Nested
    class FeedUrlMandatoryYears {

        @Test
        void shouldConsiderYearsMandatoryWhenNotCurrentYearAtEarliestTZ() {
            ZonedDateTime janFirst2004AtEarliest = ZonedDateTime.of(2004, 1, 1, 0, 0, 0, 0, NvdApiDataSource.FeedUrl.ZONE_GLOBAL_EARLIEST);
            assertTrue(isMandatoryFeedYear(janFirst2004AtEarliest, 2002));
            assertTrue(isMandatoryFeedYear(janFirst2004AtEarliest, 2003));
            assertFalse(isMandatoryFeedYear(janFirst2004AtEarliest, 2004));
        }

        @Test
        void shouldConsiderYearsMandatoryWhenNotCurrentYearAtLatestTZ() {
            ZonedDateTime janFirst2004AtLatest = ZonedDateTime.of(2004, 1, 1, 0, 0, 0, 0, NvdApiDataSource.FeedUrl.ZONE_GLOBAL_LATEST);
            assertTrue(isMandatoryFeedYear(janFirst2004AtLatest, 2002));
            assertTrue(isMandatoryFeedYear(janFirst2004AtLatest, 2003));
            assertFalse(isMandatoryFeedYear(janFirst2004AtLatest, 2004));
        }

        @Test
        void shouldConsiderYearsMandatoryWhenNoLongerJan1Anywhere() {
            // It's still Jan 1 somewhere...
            ZonedDateTime janSecond2004AtEarliest = ZonedDateTime.of(2004, 1, 2, 0, 0, 0, 0, NvdApiDataSource.FeedUrl.ZONE_GLOBAL_EARLIEST);
            assertFalse(isMandatoryFeedYear(janSecond2004AtEarliest, 2004));

            // Until it's no longer Jan 1 anywhere
            ZonedDateTime janSecond2004AtLatest = ZonedDateTime.of(2004, 1, 2, 0, 0, 0, 1, NvdApiDataSource.FeedUrl.ZONE_GLOBAL_LATEST);
            assertTrue(isMandatoryFeedYear(janSecond2004AtLatest, 2004));
        }
    }

    @Nested
    class FeedUrlMetadataRetrieval {

        @Test
        void shouldRetrieveMetadataByYear() throws Exception {
            try (MockedStatic<Downloader> downloaderClass = mockStatic(Downloader.class)) {
                Downloader downloader = mock(Downloader.class);
                when(downloader.fetchContent(any(), any())).thenReturn("lastModifiedDate=2013-01-01T12:00:00Z");
                downloaderClass.when(Downloader::getInstance).thenReturn(downloader);

                assertThat(retrieveUntil(ZonedDateTime.of(2003, 12, 1, 0, 0, 0, 0, ZoneOffset.UTC)).keySet(),
                        contains("lastModifiedDate.2002", "lastModifiedDate.2003"));
            }
        }

        @Test
        void shouldRetrieveMetadataForNextYearOnJan1AtEarliestTZ() throws Exception {
            try (MockedStatic<Downloader> downloaderClass = mockStatic(Downloader.class)) {
                Downloader downloader = mock(Downloader.class);
                when(downloader.fetchContent(any(), any())).thenReturn("lastModifiedDate=2013-01-01T12:00:00Z");
                downloaderClass.when(Downloader::getInstance).thenReturn(downloader);

                ZonedDateTime jan1Earliest = ZonedDateTime.of(2004, 1, 1, 0, 0, 0, 0, NvdApiDataSource.FeedUrl.ZONE_GLOBAL_EARLIEST);
                assertThat(retrieveUntil(jan1Earliest.minusSeconds(1)).keySet(),
                        contains("lastModifiedDate.2002", "lastModifiedDate.2003"));

                assertThat(retrieveUntil(jan1Earliest).keySet(),
                        contains("lastModifiedDate.2002", "lastModifiedDate.2003", "lastModifiedDate.2004"));

                assertThat(retrieveUntil(ZonedDateTime.of(2004, 1, 1, 0, 0, 0, 0, NvdApiDataSource.FeedUrl.ZONE_GLOBAL_LATEST)).keySet(),
                        contains("lastModifiedDate.2002", "lastModifiedDate.2003", "lastModifiedDate.2004"));
            }
        }

        @Test
        void shouldNormallyRethrowDownloadErrorsEvenIfJan1OnEndYear() throws Exception {
            try (MockedStatic<Downloader> downloaderClass = mockStatic(Downloader.class)) {
                Downloader downloader = mock(Downloader.class);
                when(downloader.fetchContent(any(), any())).thenThrow(new DownloadFailedException("failed to download"));
                downloaderClass.when(Downloader::getInstance).thenReturn(downloader);

                assertThrows(UpdateException.class, () -> retrieveUntil(ZonedDateTime.of(2003, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC)));
            }
        }

        @Test
        void shouldIgnoreDownloadFailureForFinalYearIfStillJan1() throws Exception {
            List<ZonedDateTime> untilDates = List.of(
                    ZonedDateTime.of(2004, 1, 1, 0, 0, 0, 0, NvdApiDataSource.FeedUrl.ZONE_GLOBAL_EARLIEST),
                    ZonedDateTime.of(2004, 1, 2, 0, 0, 0, 0, NvdApiDataSource.FeedUrl.ZONE_GLOBAL_LATEST)
                            .minusSeconds(1)
            );

            for (ZonedDateTime until : untilDates) {
                try (MockedStatic<Downloader> downloaderClass = mockStatic(Downloader.class)) {
                    Downloader downloader = mock(Downloader.class);
                    when(downloader.fetchContent(any(), any()))
                            .thenReturn("lastModifiedDate=2013-01-01T12:00:00Z")
                            .thenReturn("lastModifiedDate=2013-01-01T12:00:00Z")
                            .thenThrow(new DownloadFailedException("failed to download 3rd file"));

                    downloaderClass.when(Downloader::getInstance).thenReturn(downloader);

                    assertThat(retrieveUntil(until).keySet(),
                            contains("lastModifiedDate.2002", "lastModifiedDate.2003"));
                }
            }
        }

        private Map<String, ZonedDateTime> retrieveUntil(ZonedDateTime until) throws UpdateException {
            Map<String, ZonedDateTime> lastModifieds;
            NvdApiDataSource.FeedUrl feedUrl = extractFromUrlOptionalPattern("https://internal.server/nist/nvdcve-{0}.json.gz");

            lastModifieds = feedUrl.getLastModifiedDatePropertiesByYear(new Settings(), until);

            assertThat(lastModifieds.values(), everyItem(Matchers.equalTo(ZonedDateTime.of(2013, 1, 1, 12, 0, 0, 0, ZoneOffset.UTC))));
            return lastModifieds;
        }
    }

    @Nested
    class ApiUpdateFailure {

        private static final int PAGE_SIZE = 10;

        private HttpServer server;
        private Settings settings;

        @BeforeEach
        void setUp() throws IOException {
            settings = new Settings();
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            server.start();
        }

        @AfterEach
        void tearDown() {
            server.stop(0);
            settings.cleanup(true);
        }

        /**
         * The first page is ingested by a background processor; the second
         * page fails. {@code update()} must not return until the processor
         * has stopped writing, otherwise the engine closes the database
         * underneath it (#8622).
         */
        @Test
        void shouldStopProcessingBeforeReturningFromFailedUpdate() throws Exception {
            final CountDownLatch writeStarted = new CountDownLatch(1);
            final AtomicInteger inFlight = new AtomicInteger();
            final AtomicInteger written = new AtomicInteger();

            server.createContext("/", exchange -> {
                if (exchange.getRequestURI().getQuery().contains("startIndex=0")) {
                    respond(exchange, 200, page(PAGE_SIZE));
                } else {
                    try {
                        writeStarted.await(10, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    respond(exchange, 503, "");
                }
            });

            final CveDB cveDb = mock(CveDB.class);
            when(cveDb.getDatabaseProperties()).thenReturn(mock(DatabaseProperties.class));
            doAnswer(invocation -> {
                inFlight.incrementAndGet();
                try {
                    writeStarted.countDown();
                    Thread.sleep(200);
                    written.incrementAndGet();
                } finally {
                    inFlight.decrementAndGet();
                }
                return null;
            }).when(cveDb).updateVulnerability(any(), any());

            assertThrows(UpdateException.class, () -> new NvdApiDataSource().update(engineFor(cveDb)));

            assertEquals(0, inFlight.get(), "a processor was still writing to the database after update() returned");
            assertTrue(written.get() < PAGE_SIZE, "processing should stop once the update has failed, but wrote " + written.get());
        }

        private Engine engineFor(CveDB cveDb) {
            final Engine engine = mock(Engine.class);
            when(engine.getSettings()).thenReturn(settings);
            when(engine.getDatabase()).thenReturn(cveDb);
            settings.setString(Settings.KEYS.NVD_API_ENDPOINT,
                    "http://localhost:" + server.getAddress().getPort() + "/rest/json/cves/2.0");
            settings.setInt(Settings.KEYS.NVD_API_RESULTS_PER_PAGE, PAGE_SIZE);
            settings.setInt(Settings.KEYS.NVD_API_MAX_RETRY_COUNT, 1);
            return engine;
        }

        private String page(int count) {
            final StringBuilder vulns = new StringBuilder();
            for (int i = 1; i <= count; i++) {
                if (i > 1) {
                    vulns.append(',');
                }
                vulns.append(String.format("{\"cve\":{\"id\":\"CVE-2099-%04d\",\"sourceIdentifier\":\"test\","
                        + "\"published\":\"2099-01-01T00:00:00.000\",\"lastModified\":\"2099-01-01T00:00:00.000\","
                        + "\"vulnStatus\":\"Analyzed\",\"descriptions\":[{\"lang\":\"en\",\"value\":\"test\"}],"
                        + "\"references\":[]}}", i));
            }
            return String.format("{\"resultsPerPage\":%d,\"startIndex\":0,\"totalResults\":%d,\"format\":\"NVD_CVE\","
                    + "\"version\":\"2.0\",\"timestamp\":\"2099-01-01T00:00:00.000\",\"vulnerabilities\":[%s]}",
                    count, count * 2, vulns);
        }

        private void respond(HttpExchange exchange, int status, String body) throws IOException {
            final byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        }
    }
}
