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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Jeremy Long
 */
class JarAnalyzerTest extends BaseTest {

    /**
     * Test of inspect method, of class JarAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    void testAnalyze() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "maven-lib/struts2-core-2.1.2.jar");
        Dependency result = new Dependency(file);
        JarAnalyzer instance = new JarAnalyzer();
        instance.initialize(getSettings());
        instance.prepareFileTypeAnalyzer(null);
        instance.analyze(result, null);
        assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("apache"));
        assertTrue(result.getVendorWeightings().contains("apache"));

        file = BaseTest.getResourceAsFile(this, "dwr.jar");
        result = new Dependency(file);
        instance.analyze(result, null);
        assertEquals(JarAnalyzer.DEPENDENCY_ECOSYSTEM, result.getEcosystem());
        boolean found = false;
        for (Evidence e : result.getEvidence(EvidenceType.VENDOR)) {
            if (e.getName().equals("url")) {
                assertEquals("http://getahead.ltd.uk/dwr", e.getValue(), "Project url was not as expected in dwr.jar");
                found = true;
                break;
            }
        }
        assertTrue(found, "Project url was not found in dwr.jar");

        //file = new File(this.getClass().getClassLoader().getResource("org.mortbay.jetty.jar").getPath());
        file = BaseTest.getResourceAsFile(this, "org.mortbay.jetty.jar");
        result = new Dependency(file);
        instance.analyze(result, null);
        found = false;
        for (Evidence e : result.getEvidence(EvidenceType.PRODUCT)) {
            if (e.getName().equalsIgnoreCase("package-title")
                    && e.getValue().equalsIgnoreCase("org.mortbay.http")) {
                found = true;
                break;
            }
        }
        assertTrue(found, "package-title of org.mortbay.http not found in org.mortbay.jetty.jar");

        found = false;
        for (Evidence e : result.getEvidence(EvidenceType.VENDOR)) {
            if (e.getName().equalsIgnoreCase("implementation-url")
                    && e.getValue().equalsIgnoreCase("http://jetty.mortbay.org")) {
                found = true;
                break;
            }
        }
        assertTrue(found, "implementation-url of http://jetty.mortbay.org not found in org.mortbay.jetty.jar");

        found = false;
        for (Evidence e : result.getEvidence(EvidenceType.VERSION)) {
            if (e.getName().equalsIgnoreCase("Implementation-Version")
                    && e.getValue().equalsIgnoreCase("4.2.27")) {
                found = true;
                break;
            }
        }
        assertTrue(found, "implementation-version of 4.2.27 not found in org.mortbay.jetty.jar");

        //file = new File(this.getClass().getClassLoader().getResource("org.mortbay.jmx.jar").getPath());
        file = BaseTest.getResourceAsFile(this, "org.mortbay.jmx.jar");
        result = new Dependency(file);
        instance.analyze(result, null);
        assertEquals(0, result.getEvidence(EvidenceType.VERSION).size(), "org.mortbar.jmx.jar has version evidence?");
    }

    @Test
    void testAddMatchingValues() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "maven-lib/struts2-core-2.1.2.jar");
        Dependency dependency = new Dependency(file);
        JarAnalyzer instance = new JarAnalyzer();
        instance.initialize(getSettings());
        instance.prepareFileTypeAnalyzer(null);

        final List<JarAnalyzer.ClassNameInformation> classNames = instance.collectClassNames(dependency);

        JarAnalyzer.addMatchingValues(classNames, "thevelocity", dependency, EvidenceType.VENDOR);
        JarAnalyzer.addMatchingValues(classNames, "freemarkercore", dependency, EvidenceType.VENDOR);
        JarAnalyzer.addMatchingValues(classNames, "the defaultpropertiesprovidertest", dependency, EvidenceType.VENDOR);
        JarAnalyzer.addMatchingValues(classNames, "thedefaultpropertiesprovider test", dependency, EvidenceType.VENDOR);
        JarAnalyzer.addMatchingValues(classNames, "thedefaultpropertiesprovidertest", dependency, EvidenceType.VENDOR);

        assertFalse(dependency.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("velocity"));
        assertFalse(dependency.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("freemarker"));
        assertFalse(dependency.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("defaultpropertiesprovider"));

        JarAnalyzer.addMatchingValues(classNames, "strutsexception", dependency, EvidenceType.VENDOR);
        JarAnalyzer.addMatchingValues(classNames, "the velocity", dependency, EvidenceType.VENDOR);
        JarAnalyzer.addMatchingValues(classNames, "freemarker core", dependency, EvidenceType.VENDOR);
        JarAnalyzer.addMatchingValues(classNames, "the defaultpropertiesprovider test", dependency, EvidenceType.VENDOR);

        assertTrue(dependency.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("strutsexception"));
        assertTrue(dependency.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("velocity"));
        assertTrue(dependency.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("freemarker"));
        assertTrue(dependency.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("defaultpropertiesprovider"));
    }

    /**
     * Test of getSupportedExtensions method, of class JarAnalyzer.
     */
    @Test
    void testAcceptSupportedExtensions() throws Exception {
        JarAnalyzer instance = new JarAnalyzer();
        instance.initialize(getSettings());
        instance.prepare(null);
        instance.setEnabled(true);
        String[] files = {"test.jar", "test.war"};
        for (String name : files) {
            assertTrue(instance.accept(new File(name)), name);
        }
    }

    /**
     * Test of getName method, of class JarAnalyzer.
     */
    @Test
    void testGetName() {
        JarAnalyzer instance = new JarAnalyzer();
        String expResult = "Jar Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    @Test
    void testParseManifest() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "maven-lib/xalan-2.7.0.jar");
        Dependency result = new Dependency(file);
        JarAnalyzer instance = new JarAnalyzer();
        List<JarAnalyzer.ClassNameInformation> cni = new ArrayList<>();
        instance.parseManifest(result, cni);

        assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("manifest: org/apache/xalan/"));
    }

    /**
     * Test of getAnalysisPhase method, of class JarAnalyzer.
     */
    @Test
    void testGetAnalysisPhase() {
        JarAnalyzer instance = new JarAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.INFORMATION_COLLECTION;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method, of class JarAnalyzer.
     */
    @Test
    void testGetAnalyzerEnabledSettingKey() {
        JarAnalyzer instance = new JarAnalyzer();
        String expResult = Settings.KEYS.ANALYZER_JAR_ENABLED;
        String result = instance.getAnalyzerEnabledSettingKey();
        assertEquals(expResult, result);
    }

    @Test
    void testClassInformation() {
        JarAnalyzer.ClassNameInformation instance = new JarAnalyzer.ClassNameInformation("org/owasp/dependencycheck/analyzer/JarAnalyzer");
        assertEquals("org/owasp/dependencycheck/analyzer/JarAnalyzer", instance.getName());
        List<String> expected = Arrays.asList("owasp", "dependencycheck", "analyzer", "jaranalyzer");
        List<String> results = instance.getPackageStructure();
        assertEquals(expected, results);
    }

    @Test
    void testAnalyzeDependency_SkipsMacOSMetaDataFile() throws Exception {
        JarAnalyzer instance = new JarAnalyzer();
        Dependency macOSMetaDataFile = new Dependency();

        macOSMetaDataFile
                .setActualFilePath(Paths.get("src", "test", "resources", "._avro-ipc-1.5.0.jar").toFile().getAbsolutePath());
        macOSMetaDataFile.setFileName("._avro-ipc-1.5.0.jar");
        Dependency actualJarFile = new Dependency();
        actualJarFile.setActualFilePath(BaseTest.getResourceAsFile(this, "avro-ipc-1.5.0.jar").getAbsolutePath());
        actualJarFile.setFileName("avro-ipc-1.5.0.jar");
        try (Engine engine = new Engine(getSettings())) {
            engine.setDependencies(Arrays.asList(macOSMetaDataFile, actualJarFile));
            instance.analyzeDependency(macOSMetaDataFile, engine);
            assertEquals(1, engine.getDependencies().length);
        }

    }

    @Test
    void testAnalyseDependency_SkipsNonZipFile() throws Exception {
        JarAnalyzer instance = new JarAnalyzer();
        Dependency textFileWithJarExtension = new Dependency();
        textFileWithJarExtension
                .setActualFilePath(BaseTest.getResourceAsFile(this, "test.properties").getAbsolutePath());
        textFileWithJarExtension.setFileName("textFileWithJarExtension.jar");
        try (Engine engine = new Engine(getSettings())) {
            engine.setDependencies(Collections.singletonList(textFileWithJarExtension));
            instance.analyzeDependency(textFileWithJarExtension, engine);
            assertEquals(0, engine.getDependencies().length);
        }
    }
}
