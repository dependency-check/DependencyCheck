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

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.Settings;

import java.net.URI;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.everyItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
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
}
