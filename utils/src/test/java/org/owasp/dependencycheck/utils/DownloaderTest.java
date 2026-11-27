/*
 * This file is part of dependency-check-utils.
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
 * Copyright (c) 2026 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import com.sun.net.httpserver.HttpServer;
import org.apache.hc.client5.http.utils.DateUtils;
import org.apache.hc.core5.http.ContentType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests that the Downloader reports the Retry-After header of a 429 response.
 */
class DownloaderTest extends BaseTest {

    /**
     * Local server that answers every request with 429 and the configured
     * Retry-After header.
     */
    private HttpServer server;
    /**
     * Supplies the Retry-After header value for each response; returning null
     * sends no header.
     */
    private volatile Supplier<String> retryAfter;
    /**
     * The number of requests the server received.
     */
    private final AtomicInteger requests = new AtomicInteger();

    @BeforeEach
    @Override
    public void setUp() {
        super.setUp();
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            server.createContext("/", exchange -> {
                exchange.getRequestBody().readAllBytes();
                requests.incrementAndGet();
                final String value = retryAfter.get();
                if (value != null) {
                    exchange.getResponseHeaders().add("Retry-After", value);
                }
                exchange.sendResponseHeaders(429, -1);
                exchange.close();
            });
            server.start();
            Downloader.getInstance().configure(getSettings());
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    @AfterEach
    @Override
    public void tearDown() {
        server.stop(0);
        super.tearDown();
    }

    @Test
    void retryAfterSeconds() {
        retryAfter = () -> "42";
        assertEquals(Duration.ofSeconds(42), post().getRetryAfter());
    }

    @Test
    void retryAfterHttpDate() {
        retryAfter = () -> DateUtils.formatStandardDate(Instant.now().plusSeconds(120));
        final Duration wait = post().getRetryAfter();
        // HTTP dates have one-second precision, and time passes during the request
        assertTrue(wait.compareTo(Duration.ofSeconds(110)) > 0 && wait.compareTo(Duration.ofSeconds(120)) <= 0,
                "unexpected wait: " + wait);
    }

    @Test
    void retryAfterDateInThePastIsZero() {
        retryAfter = () -> DateUtils.formatStandardDate(Instant.now().minusSeconds(120));
        assertEquals(Duration.ZERO, post().getRetryAfter());
    }

    @Test
    void malformedRetryAfterIsIgnored() {
        retryAfter = () -> "soon";
        assertNull(post().getRetryAfter());
    }

    @Test
    void missingRetryAfterIsNull() {
        retryAfter = () -> null;
        assertNull(post().getRetryAfter());
    }

    @Test
    void automaticRetryDoesNotWaitForLongRetryAfter() {
        retryAfter = () -> "600";
        final long start = System.nanoTime();
        post();
        final Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
        // HttpClient retries the 429 once on its own, but must not sleep the requested ten minutes first
        assertEquals(2, requests.get());
        assertTrue(elapsed.compareTo(Duration.ofSeconds(10)) < 0, "request took " + elapsed);
    }

    private TooManyRequestsException post() {
        final URI uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/");
        return assertThrows(TooManyRequestsException.class, () -> Downloader.getInstance()
                .postBasedFetchContent(uri, "{}", ContentType.APPLICATION_JSON, Collections.emptyList()));
    }
}
