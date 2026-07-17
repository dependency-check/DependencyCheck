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
 * Copyright (c) 2017 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;

import com.sun.net.httpserver.HttpServer;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.utils.Settings;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class NodeAuditSearchTest extends BaseTest {

    @Test
    void testSubmitPackageWithBulkFallbackUsesBulkEndpoint() throws Exception {
        final AtomicInteger bulkRequests = new AtomicInteger();
        final AtomicInteger quickRequests = new AtomicInteger();
        final HttpServer server = createServer(
                200,
                "{"
                        + "\"minimist\":[{"
                        + "\"id\":1097677,"
                        + "\"url\":\"https://github.com/advisories/GHSA-xvch-5gv4-984h\","
                        + "\"title\":\"Prototype Pollution in minimist\","
                        + "\"severity\":\"critical\","
                        + "\"vulnerable_versions\":\"<0.2.4\""
                        + "}]"
                        + "}",
                200,
                "{\"advisories\":{}}",
                bulkRequests,
                quickRequests);
        try {
            final NodeAuditSearch search = createSearch(server);

            final List<Advisory> advisories = search.submitPackageWithBulkFallback(createLegacyPayload(), createDependencyMap());

            assertEquals(1, advisories.size());
            assertEquals("minimist", advisories.get(0).getModuleName());
            assertEquals(1, bulkRequests.get());
            assertEquals(0, quickRequests.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void testSubmitPackageWithBulkFallbackUsesQuickEndpointWhenBulkFails() throws Exception {
        final AtomicInteger bulkRequests = new AtomicInteger();
        final AtomicInteger quickRequests = new AtomicInteger();
        final HttpServer server = createServer(
                410,
                "{}",
                200,
                "{\"advisories\":{}}",
                bulkRequests,
                quickRequests);
        try {
            final NodeAuditSearch search = createSearch(server);

            final List<Advisory> advisories = search.submitPackageWithBulkFallback(createLegacyPayload(), createDependencyMap());

            assertEquals(0, advisories.size());
            assertEquals(1, bulkRequests.get());
            assertEquals(1, quickRequests.get());
        } finally {
            server.stop(0);
        }
    }

    private NodeAuditSearch createSearch(HttpServer server) throws Exception {
        final Settings settings = getSettings();
        settings.setString(Settings.KEYS.ANALYZER_NODE_AUDIT_URL,
                "http://localhost:" + server.getAddress().getPort() + "/-/npm/v1/security/audits");
        settings.setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_USE_CACHE, false);
        return new NodeAuditSearch(settings);
    }

    private JsonObject createLegacyPayload() {
        return Json.createObjectBuilder()
                .add("name", "test")
                .add("version", "1.0.0")
                .add("requires", Json.createObjectBuilder()
                        .add("minimist", "0.0.8"))
                .add("dependencies", Json.createObjectBuilder()
                        .add("minimist", Json.createObjectBuilder()
                                .add("version", "0.0.8")))
                .build();
    }

    private MultiValuedMap<String, String> createDependencyMap() {
        final MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        dependencyMap.put("minimist", "0.0.8");
        return dependencyMap;
    }

    private HttpServer createServer(int bulkStatus, String bulkResponse, int quickStatus, String quickResponse,
            AtomicInteger bulkRequests, AtomicInteger quickRequests) throws IOException {
        final HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/-/npm/v1/security/advisories/bulk", exchange -> {
            bulkRequests.incrementAndGet();
            respond(exchange, bulkStatus, bulkResponse);
        });
        server.createContext("/-/npm/v1/security/audits", exchange -> {
            quickRequests.incrementAndGet();
            respond(exchange, quickStatus, quickResponse);
        });
        server.start();
        return server;
    }

    private void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String response) throws IOException {
        final byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

// Tested as part of the NodeAuditAnalyzerIT.  Adding this test can cause build failures due to an external service.
//    private static final Logger LOGGER = LoggerFactory.getLogger(NodeAuditSearchTest.class);
//    private NodeAuditSearch searcher;
//
//    @BeforeEach
//    @Override
//    void setUp() throws Exception {
//        super.setUp();
//        searcher = new NodeAuditSearch(getSettings());
//    }
//
//    @Test
//    void testNodeAuditSearchPositive() throws Exception {
//        InputStream in = BaseTest.getResourceAsStream(this, "nodeaudit/package-lock.json");
//        try (JsonReader jsonReader = Json.createReader(in)) {
//            final JsonObject packageJson = jsonReader.readObject();
//            final JsonObject payload = SanitizePackage.sanitize(packageJson);
//            final List<Advisory> advisories = searcher.submitPackage(payload);
//            URLConnectionFailureException ex = assertThrows(URLConnectionFailureException.class,
//                    () -> searcher.submitPackage(payload));
//            assumeFalse(ex.getMessage().contains("Unable to connect to "));
//        }
//
//        //this should result in a cache hit
//        in = BaseTest.getResourceAsStream(this, "nodeaudit/package-lock.json");
//        try (JsonReader jsonReader = Json.createReader(in)) {
//            final JsonObject packageJson = jsonReader.readObject();
//            final JsonObject payload = SanitizePackage.sanitize(packageJson);
//            URLConnectionFailureException ex = assertThrows(URLConnectionFailureException.class,
//                    () -> searcher.submitPackage(payload));
//            assumeFalse(ex.getMessage().contains("Unable to connect to "));
//        }
//    }
//
//    void testNodeAuditSearchNegative() throws Exception {
//        InputStream in = BaseTest.getResourceAsStream(this, "nodeaudit/package.json");
//        try (JsonReader jsonReader = Json.createReader(in)) {
//            final JsonObject packageJson = jsonReader.readObject();
//            final JsonObject sanitizedJson = SanitizePackage.sanitize(packageJson);
//            URLConnectionFailureException ex = assertThrows(URLConnectionFailureException.class,
//                    () -> searcher.submitPackage(sanitizedJson));
//            assumeFalse(ex.getMessage().contains("Unable to connect to "));
//        }
//    }
}
