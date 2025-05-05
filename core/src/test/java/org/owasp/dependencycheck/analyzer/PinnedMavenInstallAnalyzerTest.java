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
 * Copyright (c) 2020 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link PinnedMavenInstallAnalyzer}.
 */
class PinnedMavenInstallAnalyzerTest extends BaseDBTestCase {

    /**
     * The analyzer to test.
     */
    private PinnedMavenInstallAnalyzer analyzer;

    /**
     * Correctly set up the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new PinnedMavenInstallAnalyzer();
        analyzer.initialize(getSettings());
        analyzer.setFilesMatched(true);
        analyzer.prepare(null);
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @AfterEach
    @Override
    public void tearDown() throws Exception {
        analyzer.close();
        super.tearDown();
    }

    @Test
    void testGetName() {
        assertEquals("Pinned Maven install Analyzer", analyzer.getName());
    }

    @Test
    void testSupportsFiles() {
        assertTrue(analyzer.accept(new File("install_maven.json")));
        assertTrue(analyzer.accept(new File("maven_install.json")));
        assertTrue(analyzer.accept(new File("maven_install_v010.json")));
        assertTrue(analyzer.accept(new File("maven_install_v2.json")));
        assertTrue(analyzer.accept(new File("rules_jvm_external_install.json")));
        assertTrue(analyzer.accept(new File("pinned_install_gplonly.json")));
        assertFalse(analyzer.accept(new File("install.json")), "should not accept Cloudflare install.json");
        assertFalse(analyzer.accept(new File("maven_install.txt")));
        assertFalse(analyzer.accept(new File("pinned.json")));
        assertFalse(analyzer.accept(new File("install.json.zip")));
    }

    /**
     * Tests that the analyzer correctly pulls dependencies out of a pinned v0.1.0 {@code maven_install.json}.
     */
    @Test
    void testAnalyzePinnedInstallJsonV010() throws Exception {
        try (Engine engine = new Engine(getSettings())) {
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "maven_install_v010.json"));
            engine.addDependency(result);
            analyzer.analyze(result, engine);
            assertFalse(ArrayUtils.contains(engine.getDependencies(), result));
            assertEquals(10, engine.getDependencies().length);
            boolean found = false;
            for (Dependency d : engine.getDependencies()) {
                if ("com.google.errorprone:error_prone_annotations".equals(d.getName())) {
                    found = true;
                    assertEquals("2.3.4", d.getVersion());
                    assertEquals(Ecosystem.JAVA, d.getEcosystem());
                }
            }
            assertTrue(found, "Expected to find com.google.errorprone:error_prone_annotations:2.3.4");
        }
    }

    /**
     * Tests that the analyzer correctly pulls dependencies out of a pinned v2 {@code maven_install.json}.
     */
    @Test
    void testAnalyzePinnedInstallJsonV2() throws Exception {
        try (Engine engine = new Engine(getSettings())) {
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "maven_install_v2.json"));
            engine.addDependency(result);
            analyzer.analyze(result, engine);
            assertFalse(ArrayUtils.contains(engine.getDependencies(), result));
            assertEquals(113, engine.getDependencies().length);
            boolean found = false;
            for (Dependency d : engine.getDependencies()) {
                if ("io.grpc:grpc-protobuf".equals(d.getName())) {
                    found = true;
                    assertEquals("1.48.1", d.getVersion());
                    assertEquals(Ecosystem.JAVA, d.getEcosystem());
                }
            }
            assertTrue(found, "Expected to find com.google.errorprone:error_prone_annotations:2.3.4");
        }
    }

    /**
     * Tests that the analyzer ignores a Cloudflare-style {@code install.json}.
     */
    @Test
    void testAnalyzeOtherInstallJson() throws Exception {
        try (Engine engine = new Engine(getSettings())) {
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "install.json"));
            engine.addDependency(result);
            analyzer.analyze(result, engine);
            assertTrue(ArrayUtils.contains(engine.getDependencies(), result));
            assertEquals(1, engine.getDependencies().length);
        }
    }
}
