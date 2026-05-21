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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class ArchiveAnalyzerIT extends BaseDBTestCase {

    /**
     * Test of getSupportedExtensions method, of class ArchiveAnalyzer.
     */
    @Test
    void testSupportsExtensions() {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(getSettings());
        Set<String> expResult = new HashSet<>();
        expResult.add("zip");
        expResult.add("war");
        expResult.add("ear");
        expResult.add("jar");
        expResult.add("sar");
        expResult.add("apk");
        expResult.add("nupkg");
        expResult.add("tar");
        expResult.add("gz");
        expResult.add("tgz");
        expResult.add("bz2");
        expResult.add("tbz2");
        expResult.add("rpm");
        for (String ext : expResult) {
            assertTrue(instance.accept(new File("test." + ext)), ext);
        }
    }

    /**
     * Test of getName method, of class ArchiveAnalyzer.
     */
    @Test
    void testGetName() {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(getSettings());
        String expResult = "Archive Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of supportsExtension method, of class ArchiveAnalyzer.
     */
    @Test
    void testSupportsExtension() {
        String extension = "test.7z"; //not supported
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(getSettings());
        assertFalse(instance.accept(new File(extension)), extension);
    }

    /**
     * Test of getAnalysisPhase method, of class ArchiveAnalyzer.
     */
    @Test
    void testGetAnalysisPhase() {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(getSettings());
        AnalysisPhase expResult = AnalysisPhase.INITIAL;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of prepare and close methods, of class ArchiveAnalyzer.
     */
    @Test
    void testInitialize() {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(getSettings());
        try {
            instance.setEnabled(true);
            instance.setFilesMatched(true);
            assertDoesNotThrow(() -> instance.prepare(null));
        } finally {
            assertDoesNotThrow(instance::close);
        }
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer.
     *
     * @throws java.lang.Exception when an error occurs
     */
    @Test
    void testAnalyze() throws Exception {
        Settings settings = getSettings();
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, false);

        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(settings);
        //trick the analyzer into thinking it is active.
        instance.accept(new File("test.ear"));
        try (Engine engine = new Engine(settings)) {

            instance.prepare(engine);
            File file = BaseTest.getResourceAsFile(this, "maven-lib/daytrader-ear-2.1.7.ear");
            Dependency dependency = new Dependency(file);

            int initial_size = engine.getDependencies().length;
            instance.analyze(dependency, engine);
            int ending_size = engine.getDependencies().length;
            assertTrue(initial_size < ending_size);
        } finally {
            instance.close();
        }
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer, with an executable jar.
     */
    @Test
    void testAnalyzeExecutableJar() throws Exception {
        Settings settings = getSettings();
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, false);

        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(settings);
        //trick the analyzer into thinking it is active.
        instance.accept(new File("test.ear"));
        try (Engine engine = new Engine(settings)) {
            instance.prepare(null);
            File file = BaseTest.getResourceAsFile(this, "bootable-0.1.0.jar");
            Dependency dependency = new Dependency(file);

            int initial_size = engine.getDependencies().length;
            instance.analyze(dependency, engine);
            int ending_size = engine.getDependencies().length;
            assertTrue(initial_size < ending_size);

        } finally {
            instance.close();
        }
    }

    @Test
    void testAnalyzeJarStaticResources() throws Exception {
        Settings settings = getSettings();
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, false);

        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(settings);
        //trick the analyzer into thinking it is active.
        instance.accept(new File("test.ear"));
        try (Engine engine = new Engine(settings)) {
            instance.prepare(null);
            File filea = BaseTest.getResourceAsFile(this, "archive/handle-a.jar");
            Dependency dependencya = new Dependency(filea);

            File fileb = BaseTest.getResourceAsFile(this, "archive/handle-b.jar");
            Dependency dependencyb = new Dependency(fileb);

            instance.analyze(dependencya, engine);
            int initial_size = engine.getDependencies().length;

            instance.analyze(dependencyb, engine);

            int ending_size = engine.getDependencies().length;
            assertNotEquals(initial_size, ending_size);

        } finally {
            instance.close();
        }
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer.
     */
    @Test
    void testAnalyzeTar() throws Exception {
        Settings settings = getSettings();
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, false);

        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(settings);
        //trick the analyzer into thinking it is active so that it will prepare
        instance.accept(new File("test.tar"));
        try (Engine engine = new Engine(settings)) {
            instance.prepare(null);

            File file = BaseTest.getResourceAsFile(this, "stagedhttp-modified.tar");
            Dependency dependency = new Dependency(file);

            int initial_size = engine.getDependencies().length;
            instance.analyze(dependency, engine);
            int ending_size = engine.getDependencies().length;
            assertTrue(initial_size < ending_size);
        } finally {
            instance.close();
        }
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer.
     */
    @Test
    void testAnalyzeTarGz() throws Exception {
        Settings settings = getSettings();
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, false);

        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(settings);
        instance.accept(new File("zip")); //ensure analyzer is "enabled"
        try (Engine engine = new Engine(settings)) {
            instance.prepare(null);

            File file = BaseTest.getResourceAsFile(this, "file.tar.gz");
            //Dependency dependency = new Dependency(file);

            int initial_size = engine.getDependencies().length;
            //instance.analyze(dependency, engine);
            engine.scan(file);
            engine.analyzeDependencies();
            int ending_size = engine.getDependencies().length;
            assertTrue(initial_size < ending_size);

        } finally {
            instance.close();
        }
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer.
     */
    @Test
    void testAnalyzeTarBz2() throws Exception {
        Settings settings = getSettings();
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, false);

        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(settings);
        instance.accept(new File("zip")); //ensure analyzer is "enabled"
        try (Engine engine = new Engine(settings)) {
            instance.prepare(null);
            File file = BaseTest.getResourceAsFile(this, "file.tar.bz2");

            int initial_size = engine.getDependencies().length;
            engine.scan(file);
            engine.analyzeDependencies();
            int ending_size = engine.getDependencies().length;
            assertTrue(initial_size < ending_size);
        } finally {
            instance.close();
        }
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer.
     */
    @Test
    void testAnalyzeTgz() throws Exception {
        Settings settings = getSettings();
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, false);

        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(settings);
        instance.accept(new File("zip")); //ensure analyzer is "enabled"
        try (Engine engine = new Engine(settings)) {
            instance.prepare(null);

            File file = BaseTest.getResourceAsFile(this, "file.tgz");
            int initial_size = engine.getDependencies().length;
            engine.scan(file);
            engine.analyzeDependencies();
            int ending_size = engine.getDependencies().length;
            assertTrue(initial_size < ending_size);

        } finally {
            instance.close();
        }
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer.
     */
    @Test
    void testAnalyzeTbz2() throws Exception {
        Settings settings = getSettings();
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, false);

        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(settings);
        instance.accept(new File("zip")); //ensure analyzer is "enabled"
        try (Engine engine = new Engine(settings)) {
            instance.prepare(null);
            File file = BaseTest.getResourceAsFile(this, "file.tbz2");
            int initial_size = engine.getDependencies().length;
            engine.scan(file);
            engine.analyzeDependencies();
            int ending_size = engine.getDependencies().length;
            assertTrue(initial_size < ending_size);
        } finally {
            instance.close();
        }
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer.
     */
    @Test
    void testAnalyzeRpm() throws Exception {
        Settings settings = getSettings();
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, false);

        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(settings);
        //trick the analyzer into thinking it is active so that it will prepare
        instance.accept(new File("struts-1.2.9-162.35.1.uyuni.noarch.rpm"));
        try (Engine engine = new Engine(settings)) {
            instance.prepare(null);

            File file = BaseTest.getResourceAsFile(this, "xmlsec-2.0.7-3.7.uyuni.noarch.rpm");
            Dependency dependency = new Dependency(file);

            int initial_size = engine.getDependencies().length;
            instance.analyze(dependency, engine);
            int ending_size = engine.getDependencies().length;
            assertTrue(initial_size < ending_size);
        } finally {
            instance.close();
        }
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer.
     */
    @Test
    void testAnalyze_badZip() throws Exception {
        Settings settings = getSettings();
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, false);

        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(settings);
        try (Engine engine = new Engine(settings)) {
            instance.prepare(null);

            File file = BaseTest.getResourceAsFile(this, "test.zip");
            Dependency dependency = new Dependency(file);
            int initial_size = engine.getDependencies().length;
//            boolean failed = false;
//            try {
            instance.analyze(dependency, engine);
//            } catch (java.lang.UnsupportedClassVersionError ex) {
//                failed = true;
//            }
//            assertTrue(failed);
            int ending_size = engine.getDependencies().length;
            assertEquals(initial_size, ending_size);
        } finally {
            instance.close();
        }
    }
}
