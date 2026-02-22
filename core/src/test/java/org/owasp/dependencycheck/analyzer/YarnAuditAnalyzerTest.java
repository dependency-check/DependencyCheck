package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import java.io.File;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class YarnAuditAnalyzerTest extends BaseTest {

    @Test
    void testGetName() {
        YarnAuditAnalyzer analyzer = new YarnAuditAnalyzer();
        assertThat(analyzer.getName(), is("Yarn Audit Analyzer"));
    }

    @Test
    void testSupportsFiles() {
        YarnAuditAnalyzer analyzer = new YarnAuditAnalyzer();
        assertThat(analyzer.accept(new File("package-lock.json")), is(false));
        assertThat(analyzer.accept(new File("npm-shrinkwrap.json")), is(false));
        assertThat(analyzer.accept(new File("yarn.lock")), is(true));
        assertThat(analyzer.accept(new File("package.json")), is(false));
    }
}
