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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class DependencyMergingAnalyzerTest extends BaseTest {

    /**
     * Test of getName method, of class DependencyMergingAnalyzer.
     */
    @Test
    void testGetName() {
        DependencyMergingAnalyzer instance = new DependencyMergingAnalyzer();
        String expResult = "Dependency Merging Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class DependencyMergingAnalyzer.
     */
    @Test
    void testGetAnalysisPhase() {
        DependencyMergingAnalyzer instance = new DependencyMergingAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.POST_INFORMATION_COLLECTION1;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method, of class
     * DependencyMergingAnalyzer.
     */
    @Test
    void testGetAnalyzerEnabledSettingKey() {
        DependencyMergingAnalyzer instance = new DependencyMergingAnalyzer();
        String expResult = Settings.KEYS.ANALYZER_DEPENDENCY_MERGING_ENABLED;
        String result = instance.getAnalyzerEnabledSettingKey();
        assertEquals(expResult, result);
    }

    /**
     * Test of evaluateDependencies method, of class DependencyMergingAnalyzer.
     */
    @Test
    void testEvaluateDependencies() {
//        Dependency dependency = null;
//        Dependency nextDependency = null;
//        Set<Dependency> dependenciesToRemove = null;
//        DependencyMergingAnalyzer instance = new DependencyMergingAnalyzer();
//        boolean expResult = false;
//        boolean result = instance.evaluateDependencies(dependency, nextDependency, dependenciesToRemove);
//        assertEquals(expResult, result);
    }

    /**
     * Test of mergeDependencies method, of class DependencyMergingAnalyzer.
     */
    @Test
    void testMergeDependencies() {
        Dependency dependency = new Dependency(true);
        dependency.setName("main");
        dependency.addEvidence(EvidenceType.VENDOR, "test", "vendor", "main", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.PRODUCT, "test", "product", "main", Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VERSION, "test", "version", "1.0", Confidence.HIGHEST);
        Dependency relatedDependency = new Dependency(true);
        relatedDependency.addEvidence(EvidenceType.VENDOR, "test", "vendor", "related", Confidence.HIGHEST);
        relatedDependency.addEvidence(EvidenceType.PRODUCT, "test", "product", "related", Confidence.HIGHEST);
        relatedDependency.addEvidence(EvidenceType.VERSION, "test", "version", "1.0", Confidence.HIGHEST);
        relatedDependency.setName("related");
        relatedDependency.addProjectReference("related");
        Set<Dependency> dependenciesToRemove = new HashSet<>();
        DependencyMergingAnalyzer.mergeDependencies(dependency, relatedDependency, dependenciesToRemove);
        assertTrue(dependenciesToRemove.contains(relatedDependency));
        assertEquals(2, dependency.getEvidence(EvidenceType.VENDOR).size());
        assertEquals(2, dependency.getEvidence(EvidenceType.PRODUCT).size());
        assertEquals(1, dependency.getEvidence(EvidenceType.VERSION).size());
        assertEquals(1, dependency.getRelatedDependencies().size());
        assertEquals(0, relatedDependency.getRelatedDependencies().size());
    }

    /**
     * Test of isSameRubyGem method, of class DependencyMergingAnalyzer.
     */
    @Test
    void testIsSameRubyGem() {
        Dependency dependency1 = new Dependency(new File("some.gemspec"), true);
        Dependency dependency2 = new Dependency(new File("another.gemspec"), true);
        dependency1.setPackagePath("path1");
        dependency2.setPackagePath("path2");
        DependencyMergingAnalyzer instance = new DependencyMergingAnalyzer();
        boolean expResult = false;
        boolean result = instance.isSameRubyGem(dependency1, dependency2);
        assertEquals(expResult, result);

        dependency2.setPackagePath("path1");
        expResult = true;
        result = instance.isSameRubyGem(dependency1, dependency2);
        assertEquals(expResult, result);
    }

    /**
     * Test of getMainGemspecDependency method, of class
     * DependencyMergingAnalyzer.
     */
    @Test
    void testGetMainGemspecDependency() {
        Dependency dependency1 = null;
        Dependency dependency2 = null;
        DependencyMergingAnalyzer instance = new DependencyMergingAnalyzer();
        Dependency expResult = null;
        Dependency result = instance.getMainGemspecDependency(dependency1, dependency2);
        assertEquals(expResult, result);

        dependency1 = new Dependency(new File("specifications/some.gemspec"), true);
        dependency1.setPackagePath("path");
        dependency1.setEcosystem(Ecosystem.RUBY);
        dependency2 = new Dependency(new File("another.gemspec"), true);
        dependency2.setEcosystem(Ecosystem.RUBY);
        dependency2.setPackagePath("path");
        expResult = dependency1;
        result = instance.getMainGemspecDependency(dependency1, dependency2);
        assertEquals(expResult, result);

        dependency1 = new Dependency(new File("some.gemspec"), true);
        dependency1.setEcosystem(Ecosystem.RUBY);
        dependency1.setPackagePath("path");
        dependency2 = new Dependency(new File("specifications/another.gemspec"), true);
        dependency2.setEcosystem(Ecosystem.RUBY);
        dependency2.setPackagePath("path");
        expResult = dependency2;
        result = instance.getMainGemspecDependency(dependency1, dependency2);
        assertEquals(expResult, result);
    }

    /**
     * Test of isSameSwiftPackage method, of class DependencyMergingAnalyzer.
     */
    @Test
    void testIsSameSwiftPackage() {
        Dependency dependency1 = new Dependency(new File("Package.swift"), true);
        Dependency dependency2 = new Dependency(new File("Package.swift"), true);
        dependency1.setPackagePath("path1");
        dependency2.setPackagePath("path2");
        DependencyMergingAnalyzer instance = new DependencyMergingAnalyzer();
        boolean expResult = false;
        boolean result = instance.isSameSwiftPackage(dependency1, dependency2);
        assertEquals(expResult, result);

        dependency2.setPackagePath("path1");
        expResult = true;
        result = instance.isSameSwiftPackage(dependency1, dependency2);
        assertEquals(expResult, result);
    }

    /**
     * Test of getMainSwiftDependency method, of class
     * DependencyMergingAnalyzer.
     */
    @Test
    void testGetMainSwiftDependency() {

        Dependency dependency1 = null;
        Dependency dependency2 = null;
        DependencyMergingAnalyzer instance = new DependencyMergingAnalyzer();
        Dependency expResult = null;
        Dependency result = instance.getMainSwiftDependency(dependency1, dependency2);
        assertEquals(expResult, result);

        dependency1 = new Dependency(new File("some.podspec"), true);
        dependency1.setEcosystem(Ecosystem.IOS);
        dependency1.setPackagePath("path");
        dependency2 = new Dependency(new File("Package.swift"), true);
        dependency2.setEcosystem(Ecosystem.IOS);
        dependency2.setPackagePath("path");
        expResult = dependency1;
        result = instance.getMainSwiftDependency(dependency1, dependency2);
        assertEquals(expResult, result);

        dependency1 = new Dependency(new File("Package.swift"), true);
        dependency1.setEcosystem(Ecosystem.IOS);
        dependency1.setPackagePath("path");
        dependency2 = new Dependency(new File("some.podspec"), true);
        dependency2.setEcosystem(Ecosystem.IOS);
        dependency2.setPackagePath("path");
        expResult = dependency2;
        result = instance.getMainSwiftDependency(dependency1, dependency2);
        assertEquals(expResult, result);
    }

    /**
     * Test of getMainAndroidDependency method, of class
     * DependencyMergingAnalyzer.
     *
     * @throws Exception thrown if there is an analysis exception
     */
    @Test
    void testGetMainAndroidDependency() throws Exception {
        ArchiveAnalyzer aa = null;
        try (Engine engine = new Engine(Engine.Mode.EVIDENCE_COLLECTION, getSettings())) {
            Dependency dependency1 = new Dependency(BaseTest.getResourceAsFile(this, "maven-lib/aar-1.0.0.aar"));
            dependency1.setEcosystem(Ecosystem.JAVA);
            aa = new ArchiveAnalyzer();

            aa.initialize(getSettings());
            aa.accept(dependency1.getActualFile());
            aa.prepareAnalyzer(engine);
            aa.analyze(dependency1, engine);

            Dependency dependency2 = null;
            for (Dependency d : engine.getDependencies()) {
                if ("classes.jar".equals(d.getActualFile().getName())) {
                    dependency2 = d;
                    break;
                }
            }
            assertNotNull(dependency2, "classes.jar was not found");
            dependency2.setEcosystem(Ecosystem.JAVA);
            DependencyMergingAnalyzer instance = new DependencyMergingAnalyzer();
            Dependency expResult = dependency1;
            Dependency result = instance.getMainAndroidDependency(dependency1, dependency2);
            assertEquals(expResult, result);
        } finally {
            if (aa != null) {
                aa.closeAnalyzer();
            }
        }
    }

    /**
     * Test of getMainDotnetDependency method, of class
     * DependencyMergingAnalyzer.
     */
    @Test
    void testGetMainDotnetDependency() {
        Dependency dependency1 = new Dependency(BaseTest.getResourceAsFile(this, "log4net.dll"));
        dependency1.setEcosystem(AssemblyAnalyzer.DEPENDENCY_ECOSYSTEM);
        dependency1.setName("log4net");
        dependency1.setVersion("1.2.13");
        Dependency dependency2 = new Dependency(true);
        dependency2.setEcosystem(NugetconfAnalyzer.DEPENDENCY_ECOSYSTEM);
        dependency2.setName("test");
        dependency2.setVersion("1.2.13");
        DependencyMergingAnalyzer instance = new DependencyMergingAnalyzer();
        Dependency expResult = null;
        Dependency result = instance.getMainDotnetDependency(dependency1, dependency2);
        assertEquals(expResult, result);
        dependency2.setName("log4net");
        expResult = dependency1;
        result = instance.getMainDotnetDependency(dependency1, dependency2);
        assertEquals(expResult, result);
        result = instance.getMainDotnetDependency(dependency2, dependency1);
        assertEquals(expResult, result);
    }

}
