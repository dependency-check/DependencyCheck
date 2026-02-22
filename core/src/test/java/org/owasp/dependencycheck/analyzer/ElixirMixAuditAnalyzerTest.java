package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class ElixirMixAuditAnalyzerTest extends BaseTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(ElixirMixAuditAnalyzerTest.class);
    private ElixirMixAuditAnalyzer analyzer;

    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        analyzer = new ElixirMixAuditAnalyzer();
        analyzer.initialize(getSettings());
        analyzer.setFilesMatched(true);
    }

    @AfterEach
    public void tearDown() throws Exception {
        if (analyzer != null) {
            analyzer.close();
            analyzer = null;
        }
    }

    @Test
    void testGetName() {
        assertThat(analyzer.getName(), is("Elixir Mix Audit Analyzer"));
    }

    @Test
    void testSupportsFiles() {
        assertThat(analyzer.accept(new File("mix.lock")), is(true));
    }
}
