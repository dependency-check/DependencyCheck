package org.owasp.dependencycheck.data.elixir;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MixAuditJsonParserTest {

    @Test
    void testEmptyResult() throws AnalysisException, FileNotFoundException {
        MixAuditJsonParser parser;

        File jsonFixtureFile = BaseTest.getResourceAsFile(this, "elixir/mix_audit/empty.json");
        FileReader fir = new FileReader(jsonFixtureFile);

        parser = new MixAuditJsonParser(fir);
        parser.process();

        assertEquals(0, parser.getResults().size(), "results must be empty");
    }

    @Test
    void testSingleResult() throws AnalysisException, FileNotFoundException {
        MixAuditJsonParser parser;

        File jsonFixtureFile = BaseTest.getResourceAsFile(this, "elixir/mix_audit/plug.json");
        FileReader fir = new FileReader(jsonFixtureFile);

        parser = new MixAuditJsonParser(fir);
        parser.process();

        assertEquals(1, parser.getResults().size(), "must have 1 result");

        MixAuditResult r = parser.getResults().get(0);
        assertEquals("dc96aba4-4462-4d3b-b73f-28b9349133d8", r.getId());
        assertEquals("2018-1000883", r.getCve());
        assertEquals("Header Injection\n", r.getTitle());
        assertEquals("Cookie headers were not validated\n", r.getDescription());
        assertEquals("https://github.com/elixir-plug/plug/commit/8857f8ab4acf9b9c22e80480dae2636692f5f573", r.getUrl());
        assertEquals("/DependencyCheck/core/src/test/resources/elixir/vulnerable/mix.lock", r.getDependencyLockfile());
        assertEquals("plug", r.getDependencyPackage());
        assertEquals("1.3.4", r.getDependencyVersion());
    }
}
