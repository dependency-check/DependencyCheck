package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;

import java.io.File;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for DartAnalyzer
 *
 * @author Marc Rödder
 */
class DartAnalyzerTest extends BaseTest {

    /**
     * The analyzer to test.
     */
    private DartAnalyzer dartAnalyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        dartAnalyzer = new DartAnalyzer();
        dartAnalyzer.initialize(getSettings());
        dartAnalyzer.setFilesMatched(true);
        dartAnalyzer.prepare(null);
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @AfterEach
    @Override
    public void tearDown() throws Exception {
        dartAnalyzer.close();
        dartAnalyzer = null;

        super.tearDown();
    }

    /**
     * Test of getName method, of class DartAnalyzer.
     */
    @Test
    void testDartAnalyzerGetName() {
        assertThat(dartAnalyzer.getName(), is("Dart Package Analyzer"));
    }


    /**
     * Test of supportsFiles method, of class DartAnalyzer.
     */
    @Test
    void testAnalyzerSupportsFiles() {
        assertThat(dartAnalyzer.accept(new File("pubspec.yaml")), is(true));
        assertThat(dartAnalyzer.accept(new File("pubspec.lock")), is(true));
    }

    /**
     * Test of analyze method, of class DartAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testDartPubspecLockAnalyzer() throws AnalysisException {
        final Engine engine = new Engine(getSettings());
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "dart/pubspec.lock"));
        dartAnalyzer.analyze(result, engine);

        assertThat(engine.getDependencies().length, equalTo(5));

        Dependency dependency1 = engine.getDependencies()[0];
        Dependency dependency2 = engine.getDependencies()[1];
        Dependency dependency3 = engine.getDependencies()[2];
        Dependency dependency4 = engine.getDependencies()[3];
        Dependency dependency5 = engine.getDependencies()[4];

        assertThat(dependency1.getName(), equalTo("_fe_analyzer_shared"));
        assertThat(dependency1.getVersion(), equalTo("40.0.0"));
        for (Identifier identifier : dependency1.getSoftwareIdentifiers()) {
            if (identifier instanceof GenericIdentifier) {
                assertThat(identifier.getValue(), equalTo("cpe:2.3:a:*:_fe_analyzer_shared:40.0.0:*:*:*:*:*:*:*"));
            }
            if (identifier instanceof PurlIdentifier) {
                assertThat(identifier.getValue(), equalTo("pkg:pub/_fe_analyzer_shared@40.0.0"));
            }
        }

        assertThat(dependency2.getName(), equalTo("analyzer"));
        assertThat(dependency2.getVersion(), equalTo("4.1.0"));

        assertThat(dependency3.getName(), equalTo("build_runner"));
        assertThat(dependency3.getVersion(), equalTo("2.1.11"));

        assertThat(dependency4.getName(), equalTo("collection"));
        assertThat(dependency4.getVersion(), equalTo("1.16.0"));

        assertThat(dependency5.getName(), equalTo("dart_software_development_kit"));
        assertThat(dependency5.getVersion(), equalTo("2.17.0"));
    }

    @Test
    void testDartPubspecYamlAnalyzer() throws AnalysisException {
        final Engine engine = new Engine(getSettings());
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "dart.yaml/pubspec.yaml"));
        dartAnalyzer.analyze(result, engine);

        assertThat(engine.getDependencies().length, equalTo(7));

        Dependency dependency1 = engine.getDependencies()[0];
        Dependency dependency2 = engine.getDependencies()[1];
        Dependency dependency3 = engine.getDependencies()[2];
        Dependency dependency4 = engine.getDependencies()[3];
        Dependency dependency5 = engine.getDependencies()[4];
        Dependency dependency6 = engine.getDependencies()[5];
        Dependency dependency7 = engine.getDependencies()[6];

        assertThat(dependency1.getName(), equalTo("auto_size_text"));
        assertThat(dependency1.getVersion(), equalTo("3.0.0"));
        for (Identifier identifier : dependency1.getSoftwareIdentifiers()) {
            if (identifier instanceof GenericIdentifier) {
                assertThat(identifier.getValue(), equalTo("cpe:2.3:a:*:auto_size_text:3.0.0:*:*:*:*:*:*:*"));
            }
            if (identifier instanceof PurlIdentifier) {
                assertThat(identifier.getValue(), equalTo("pkg:pub/auto_size_text@3.0.0"));
            }
        }

        assertThat(dependency2.getName(), equalTo("carousel_slider"));
        assertThat(dependency2.getVersion(), equalTo(""));
        for (Identifier identifier : dependency2.getSoftwareIdentifiers()) {
            if (identifier instanceof GenericIdentifier) {
                assertThat(identifier.getValue(), equalTo("cpe:2.3:a:*:carousel_slider:*:*:*:*:*:*:*:*"));
            }
            if (identifier instanceof PurlIdentifier) {
                assertThat(identifier.getValue(), equalTo("pkg:pub/carousel_slider"));
            }
        }

        assertThat(dependency3.getName(), equalTo("collection"));
        assertThat(dependency3.getVersion(), equalTo("1.16.0"));

        assertThat(dependency4.getName(), equalTo("corsac_jwt"));
        assertThat(dependency4.getVersion(), equalTo("1.0.0-nullsafety.1"));

        assertThat(dependency5.getName(), equalTo("build_runner"));
        assertThat(dependency5.getVersion(), equalTo("2.1.11"));

        assertThat(dependency6.getName(), equalTo("flutter_test"));
        assertThat(dependency6.getVersion(), equalTo(""));
        for (Identifier identifier : dependency6.getSoftwareIdentifiers()) {
            if (identifier instanceof GenericIdentifier) {
                assertThat(identifier.getValue(), equalTo("cpe:2.3:a:*:flutter_test:*:*:*:*:*:*:*:*"));
            }
            if (identifier instanceof PurlIdentifier) {
                assertThat(identifier.getValue(), equalTo("pkg:pub/flutter_test"));
            }
        }

        assertThat(dependency7.getName(), equalTo("dart_software_development_kit"));
        assertThat(dependency7.getVersion(), equalTo("2.17.0"));
    }

    /**
     * Test case for issue #5008.
     * @throws AnalysisException
     */
    @Test
    void testDartPubspecYamlAnalyzerAddressbook() throws AnalysisException {
        final Engine engine = new Engine(getSettings());
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "dart.addressbook/pubspec.yaml"));
        dartAnalyzer.analyze(result, engine);

        assertThat(engine.getDependencies().length, equalTo(1));

        Dependency dependency1 = engine.getDependencies()[0];

        assertThat(dependency1.getName(), equalTo("protobuf"));
        assertThat(dependency1.getVersion(), equalTo(""));
    }

    @Test
    void testIsEnabledIsTrueByDefault() {
        assertTrue(dartAnalyzer.isEnabled());
    }
}
