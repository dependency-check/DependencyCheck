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
 * Copyright (c) 2016 Bianca Jiang. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;

import java.io.File;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for {@link RubyBundlerAnalyzer}.
 *
 * @author Bianca Jiang
 */
class RubyBundlerAnalyzerTest extends BaseTest {

    /**
     * The analyzer to test.
     */
    private RubyBundlerAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new RubyBundlerAnalyzer();
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
     * Test Analyzer name.
     */
    @Test
    void testGetName() {
        assertThat(analyzer.getName(), is("Ruby Bundler Analyzer"));
    }

    /**
     * Test Ruby Gemspec file support.
     */
    @Test
    void testSupportsFiles() {
        assertThat(analyzer.accept(new File("test.gemspec")), is(false));
        assertThat(analyzer.accept(new File("specifications" + File.separator + "test.gemspec")), is(true));
        assertThat(analyzer.accept(new File("gemspec.lock")), is(false));
    }

    /**
     * Test Ruby Bundler created gemspec analysis.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testAnalyzeGemspec() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "ruby/vulnerable/gems/rails-4.1.15/vendor/bundle/ruby/2.2.0/specifications/dalli-2.7.5.gemspec"));
        analyzer.analyze(result, null);

        final String vendorString = result.getEvidence(EvidenceType.VENDOR).toString();
        assertThat(vendorString, containsString("Peter M. Goldstein"));
        assertThat(vendorString, containsString("Mike Perham"));
        assertThat(vendorString, containsString("peter.m.goldstein@gmail.com"));
        assertThat(vendorString, containsString("https://github.com/petergoldstein/dalli"));
        assertThat(vendorString, containsString("MIT"));
        assertThat(result.getEvidence(EvidenceType.PRODUCT).toString(), containsString("dalli"));
        assertThat(result.getEvidence(EvidenceType.PRODUCT).toString(), containsString("High performance memcached client for Ruby"));
        assertThat(result.getEvidence(EvidenceType.VERSION).toString(), containsString("2.7.5"));
        assertEquals("dalli", result.getName());
        assertEquals("2.7.5", result.getVersion());
        assertEquals(RubyBundlerAnalyzer.DEPENDENCY_ECOSYSTEM, result.getEcosystem());
        assertEquals("dalli:2.7.5", result.getDisplayFileName());
    }
}
