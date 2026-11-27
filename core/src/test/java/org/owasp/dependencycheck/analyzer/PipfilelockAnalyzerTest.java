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
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for PipfilelockAnalyzerTest.
 */
class PipfilelockAnalyzerTest extends BaseDBTestCase {

    /**
     * The analyzer to test.
     */
    private PipfilelockAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new PipfilelockAnalyzer();
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

    /**
     * Test of getName method, of class PipAnalyzer.
     */
    @Test
    void testGetName() {
        assertEquals("Pipfile.lock Analyzer", analyzer.getName());
    }

    /**
     * Test of supportsExtension method, of class PipAnalyzer.
     */
    @Test
    void testSupportsFiles() {
        assertFalse(analyzer.accept(new File("Pipfile")));
        assertTrue(analyzer.accept(new File("Pipfile.lock")));
    }

    @Test
    void testAnalyzePackageLock() throws Exception {
        try (Engine engine = new Engine(getSettings())) {
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "pip/Pipfile.lock"));
            engine.addDependency(result);
            analyzer.analyze(result, engine);
            assertFalse(ArrayUtils.contains(engine.getDependencies(), result));
            assertEquals(76, engine.getDependencies().length);
            boolean found = false;
            for (Dependency d : engine.getDependencies()) {
                if ("alabaster".equals(d.getName())) {
                    found = true;
                    assertEquals("0.7.12", d.getVersion());
                    assertThat(d.getDisplayFileName(), equalTo("alabaster:0.7.12"));
                    assertEquals(PythonDistributionAnalyzer.DEPENDENCY_ECOSYSTEM, d.getEcosystem());
                    break;
                }
            }
            assertTrue(found, "Expeced to find urllib3");
        }
    }

    @Test
    void testAnalyzeDefaultSectionWithEmptyDevelop(@TempDir Path tempDir) throws Exception {
        final Path lockFile = tempDir.resolve("Pipfile.lock");
        Files.writeString(lockFile, "{\n"
                + "  \"_meta\": {\n"
                + "    \"pipfile-spec\": 6,\n"
                + "    \"requires\": {},\n"
                + "    \"sources\": []\n"
                + "  },\n"
                + "  \"default\": {\n"
                + "    \"django\": {\n"
                + "      \"index\": \"pypi\",\n"
                + "      \"version\": \"==3.2.1\"\n"
                + "    },\n"
                + "    \"urllib3\": {\n"
                + "      \"version\": \"==1.26.4\"\n"
                + "    }\n"
                + "  },\n"
                + "  \"develop\": {}\n"
                + "}\n", StandardCharsets.UTF_8);

        try (Engine engine = new Engine(getSettings())) {
            final Dependency result = new Dependency(lockFile.toFile());
            engine.addDependency(result);
            analyzer.analyze(result, engine);
            assertFalse(ArrayUtils.contains(engine.getDependencies(), result));
            final Dependency[] deps = engine.getDependencies();
            assertEquals(2, deps.length);
            final Map<String, Dependency> byName = Arrays.stream(deps)
                    .collect(Collectors.toMap(Dependency::getName, d -> d));
            assertEquals("3.2.1", byName.get("django").getVersion());
            assertEquals("1.26.4", byName.get("urllib3").getVersion());
            assertTrue(byName.get("django").getSoftwareIdentifiers().stream()
                    .anyMatch(id -> "pkg:pypi/django@3.2.1".equals(id.getValue())));
            assertTrue(byName.get("urllib3").getSoftwareIdentifiers().stream()
                    .anyMatch(id -> "pkg:pypi/urllib3@1.26.4".equals(id.getValue())));
            assertEquals(PythonDistributionAnalyzer.DEPENDENCY_ECOSYSTEM, byName.get("django").getEcosystem());
        }
    }

    @Test
    void testAnalyzeDefaultAndDevelopSectionsDeduplicatesOverlap(@TempDir Path tempDir) throws Exception {
        final Path lockFile = tempDir.resolve("Pipfile.lock");
        Files.writeString(lockFile, "{\n"
                + "  \"default\": {\n"
                + "    \"requests\": {\n"
                + "      \"version\": \"==2.31.0\"\n"
                + "    },\n"
                + "    \"certifi\": {\n"
                + "      \"version\": \"==2024.2.2\"\n"
                + "    }\n"
                + "  },\n"
                + "  \"develop\": {\n"
                + "    \"certifi\": {\n"
                + "      \"version\": \"==2024.2.2\"\n"
                + "    },\n"
                + "    \"pytest\": {\n"
                + "      \"version\": \"==8.0.0\"\n"
                + "    }\n"
                + "  }\n"
                + "}\n", StandardCharsets.UTF_8);

        try (Engine engine = new Engine(getSettings())) {
            final Dependency result = new Dependency(lockFile.toFile());
            engine.addDependency(result);
            analyzer.analyze(result, engine);
            final Dependency[] deps = engine.getDependencies();
            assertEquals(3, deps.length);
            final Map<String, Dependency> byName = Arrays.stream(deps)
                    .collect(Collectors.toMap(Dependency::getName, d -> d));
            assertEquals("2.31.0", byName.get("requests").getVersion());
            assertEquals("2024.2.2", byName.get("certifi").getVersion());
            assertEquals("8.0.0", byName.get("pytest").getVersion());
        }
    }

    @Test
    void testAnalyzeMissingAndNullSectionsAndVersions(@TempDir Path tempDir) throws Exception {
        final Path onlyDefault = tempDir.resolve("only-default").resolve("Pipfile.lock");
        Files.createDirectories(onlyDefault.getParent());
        Files.writeString(onlyDefault, "{\n"
                + "  \"default\": {\n"
                + "    \"flask\": {\n"
                + "      \"version\": \"==3.0.2\"\n"
                + "    },\n"
                + "    \"local-pkg\": {\n"
                + "      \"editable\": true,\n"
                + "      \"path\": \".\"\n"
                + "    },\n"
                + "    \"null-version-pkg\": {\n"
                + "      \"version\": null\n"
                + "    }\n"
                + "  }\n"
                + "}\n", StandardCharsets.UTF_8);

        final Path nullDevelop = tempDir.resolve("null-develop").resolve("Pipfile.lock");
        Files.createDirectories(nullDevelop.getParent());
        Files.writeString(nullDevelop, "{\n"
                + "  \"default\": null,\n"
                + "  \"develop\": null\n"
                + "}\n", StandardCharsets.UTF_8);

        try (Engine engine = new Engine(getSettings())) {
            analyzer.analyze(new Dependency(onlyDefault.toFile()), engine);
            analyzer.analyze(new Dependency(nullDevelop.toFile()), engine);
            final Dependency[] deps = engine.getDependencies();
            assertEquals(1, deps.length);
            assertEquals("flask", deps[0].getName());
            assertEquals("3.0.2", deps[0].getVersion());
        }
    }

    @Test
    void testPipfileSkippedWhenPipfileLockPresentWithDefaultPackages(@TempDir Path tempDir) throws Exception {
        final Path pipfile = tempDir.resolve("Pipfile");
        Files.writeString(pipfile, "[packages]\ndjango = \"==3.2.1\"\n", StandardCharsets.UTF_8);
        final Path lockFile = tempDir.resolve("Pipfile.lock");
        Files.writeString(lockFile, "{\n"
                + "  \"default\": {\n"
                + "    \"django\": {\n"
                + "      \"version\": \"==3.2.1\"\n"
                + "    }\n"
                + "  },\n"
                + "  \"develop\": {}\n"
                + "}\n", StandardCharsets.UTF_8);

        final PipfileAnalyzer pipfileAnalyzer = new PipfileAnalyzer();
        pipfileAnalyzer.initialize(getSettings());
        pipfileAnalyzer.setFilesMatched(true);
        pipfileAnalyzer.prepare(null);
        try (Engine engine = new Engine(getSettings())) {
            final Dependency pipfileDep = new Dependency(pipfile.toFile());
            final Dependency lockDep = new Dependency(lockFile.toFile());
            engine.addDependency(pipfileDep);
            engine.addDependency(lockDep);
            pipfileAnalyzer.analyze(pipfileDep, engine);
            analyzer.analyze(lockDep, engine);
            final Dependency[] deps = engine.getDependencies();
            assertEquals(1, deps.length);
            assertEquals("django", deps[0].getName());
            assertEquals("3.2.1", deps[0].getVersion());
        } finally {
            pipfileAnalyzer.close();
        }
    }
}
