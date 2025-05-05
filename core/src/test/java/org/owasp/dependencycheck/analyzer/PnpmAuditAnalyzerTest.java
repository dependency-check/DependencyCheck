package org.owasp.dependencycheck.analyzer;

import org.apache.commons.io.IOUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.data.nodeaudit.NpmAuditParser;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class PnpmAuditAnalyzerTest extends BaseTest
{

    @Test
    void testNpmAuditParserCompatibility() throws IOException, JSONException
    {
        NpmAuditParser npmAuditParser = new NpmAuditParser();
        JSONObject vulnsAuditJson = new JSONObject(IOUtils.toString(getResourceAsStream(this, "pnpmaudit/pnpm-audit.json"), StandardCharsets.UTF_8));
        List<Advisory> advisories = npmAuditParser.parse(vulnsAuditJson);
        assertThat(advisories.size(), is(2));
    }

    @Test
    void testSupportsFiles() {
        PnpmAuditAnalyzer analyzer = new PnpmAuditAnalyzer();
        assertThat(analyzer.accept(new File("package-lock.json")), is(false));
        assertThat(analyzer.accept(new File("npm-shrinkwrap.json")), is(false));
        assertThat(analyzer.accept(new File("yarn.lock")), is(false));
        assertThat(analyzer.accept(new File("pnpm-lock.yaml")), is(true));
    }
}
