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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 * @author jeremy long
 */
@SuppressWarnings("unchecked")
class PerlCpanfileAnalyzerTest extends BaseTest {

    /**
     * Test of getName method, of class PerlCpanfileAnalyzer.
     */
    @Test
    void testGetName() {
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer();
        String expResult = "Perl cpanfile Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class PerlCpanfileAnalyzer.
     */
    @Test
    void testGetAnalysisPhase() {
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.INFORMATION_COLLECTION;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method, of class
     * PerlCpanfileAnalyzer.
     */
    @Test
    void testGetAnalyzerEnabledSettingKey() {
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer();
        String expResult = Settings.KEYS.ANALYZER_CPANFILE_ENABLED;
        String result = instance.getAnalyzerEnabledSettingKey();
        assertEquals(expResult, result);
    }

    @Test
    void testProcessFileContents() throws AnalysisException {
        Dependency d = new Dependency();
        List<String> dependencyLines = Arrays.asList("requires 'Plack', '1.0'",
                "requires 'JSON', '>= 2.00, < 2.80'",
                "requires 'Mojolicious::Plugin::ZAPI' => '>= 2.015",
                "requires 'Hash::MoreUtils' => '>= 0.05",
                "requires 'JSON::MaybeXS' => '>= 1.002004'",
                "requires 'Test::MockModule'");
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer();
        Engine engine = new Engine(getSettings());
        instance.processFileContents(dependencyLines, "./cpanfile", engine);

        assertEquals(6, engine.getDependencies().length);
    }

    @Test
    void testProcessSingleFileContents() throws AnalysisException {
        Dependency d = new Dependency();
        List<String> dependencyLines = Arrays.asList("requires 'JSON', '>= 2.00, < 2.80'");
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer();
        Engine engine = new Engine(getSettings());
        instance.processFileContents(dependencyLines, "./cpanfile", engine);

        assertEquals(1, engine.getDependencies().length);
        Dependency dep = engine.getDependencies()[0];
        assertEquals("'JSON', '2.00'", dep.getDisplayFileName());
        assertEquals("2.00", dep.getVersion());
        assertEquals("pkg:cpan/JSON@2.00", dep.getSoftwareIdentifiers().iterator().next().getValue());
    }

    @Test
    void testProcessDefaultZero() throws AnalysisException {
        Dependency d = new Dependency();
        List<String> dependencyLines = Arrays.asList("requires 'JSON'");
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer();
        Engine engine = new Engine(getSettings());
        instance.processFileContents(dependencyLines, "./cpanfile", engine);

        assertEquals(1, engine.getDependencies().length);
        Dependency dep = engine.getDependencies()[0];
        assertEquals("'JSON', '0'", dep.getDisplayFileName());
        assertEquals("0", dep.getVersion());
        assertEquals("pkg:cpan/JSON@0", dep.getSoftwareIdentifiers().iterator().next().getValue());
    }

    @Test
    @SuppressWarnings("unchecked")
    void testPrepareContent() {
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer();
        String content = "requires 'JSON'; #any version";
        List<String> expResult = Arrays.asList("requires 'JSON'");
        List<String> result = instance.prepareContents(content);
        assertEquals(expResult, result);

        content = "requires 'JSON'; requires 'XML';";
        expResult = Arrays.asList("requires 'JSON'", "requires 'XML'");
        result = instance.prepareContents(content);
        assertEquals(expResult, result);
        content = "requires 'JSON';\n     requires 'XML';";
        expResult = Arrays.asList("requires 'JSON'", "requires 'XML'");
        result = instance.prepareContents(content);
        assertEquals(expResult, result);

        content = "requires 'JSON';# requires 'XML';";
        expResult = Arrays.asList("requires 'JSON'");
        result = instance.prepareContents(content);
        assertEquals(expResult, result);
    }
}
