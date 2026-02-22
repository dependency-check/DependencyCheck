package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import java.io.File;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class NodeAuditAnalyzerTest extends BaseTest {

    @Test
    void testGetName() {
        NodeAuditAnalyzer analyzer = new NodeAuditAnalyzer();
        assertThat(analyzer.getName(), is("Node Audit Analyzer"));
    }

    @Test
    void testSupportsFiles() {
        NodeAuditAnalyzer analyzer = new NodeAuditAnalyzer();
        assertThat(analyzer.accept(new File("package-lock.json")), is(true));
        assertThat(analyzer.accept(new File("npm-shrinkwrap.json")), is(true));
        assertThat(analyzer.accept(new File("yarn.lock")), is(false));
        assertThat(analyzer.accept(new File("package.json")), is(false));
    }
}
