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

import org.owasp.dependencycheck.BaseTest;

class NodeAuditSearchTest extends BaseTest {

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
