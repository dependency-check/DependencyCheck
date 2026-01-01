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

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.owasp.dependencycheck.data.update.NvdApiDataSource.FeedUrl.DEFAULT_FILE_PATTERN;
import static org.owasp.dependencycheck.data.update.NvdApiDataSource.FeedUrl.extractFromUrlOptionalPattern;

/**
 *
 * @author Jeremy Long
 */
class NvdApiDataSourceTest {

    @Nested
    class FeedUrl {

        @Test
        void shouldExtractUrlWithPattern() throws Exception {
            String nvdDataFeedUrl = "https://internal.server/nist/nvdcve-{0}.json.gz";
            String expectedUrl = "https://internal.server/nist/nvdcve-2045.json.gz";
            NvdApiDataSource.FeedUrl result = extractFromUrlOptionalPattern(nvdDataFeedUrl);

            assertEquals(expectedUrl, result.toFormattedUrlString("2045"));
            assertEquals(URI.create(expectedUrl).toURL(), result.toFormattedUrl("2045"));
            assertEquals(URI.create("https://internal.server/nist/some-file.txt").toURL(), result.toSuffixedUrl("some-file.txt"));

            assertEquals(expectedUrl, result.toFormattedUrlString(2045));
            assertEquals(URI.create(expectedUrl).toURL(), result.toFormattedUrl(2045));
        }

        @Test
        void shouldAllowTransformingFilePattern() throws Exception {
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
        void extractUrlWithoutPatternShouldAddTrailingSlashes() throws Exception {
            String nvdDataFeedUrl = "https://internal.server/nist";
            String expectedUrl = "https://internal.server/nist/nvdcve-2045.json.gz";

            NvdApiDataSource.FeedUrl result = extractFromUrlOptionalPattern(nvdDataFeedUrl)
                    .withPattern(p -> p.orElse(DEFAULT_FILE_PATTERN));

            assertEquals(expectedUrl, result.toFormattedUrlString("2045"));
        }
    }
}
