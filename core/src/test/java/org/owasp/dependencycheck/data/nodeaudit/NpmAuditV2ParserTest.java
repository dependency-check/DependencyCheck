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
 * Copyright (c) 2021 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;

import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;

class NpmAuditV2ParserTest extends BaseTest {

    @Test
    void testParseReturnsAdvisoryWithExpectedFields() throws IOException, JSONException {
        final NpmAuditV2Parser parser = new NpmAuditV2Parser();
        final JSONObject v2Json = new JSONObject(
                IOUtils.toString(getResourceAsStream(this, "nodeaudit/npm-audit-v2.json"), StandardCharsets.UTF_8));
        final File directory = getResourceAsFile(this, "nodeaudit/npm-audit-v2");

        final List<Advisory> advisories = parser.parse(v2Json, directory);

        assertThat(advisories.size(), is(1));
        final Advisory advisory = advisories.get(0);
        assertThat(advisory.getModuleName(), is("uglify-js"));
        assertThat(advisory.getVersion(), is("2.4.24"));
        assertThat(advisory.getGhsaId(), notNullValue());
        assertThat(advisory.getGhsaId(), startsWith("GHSA-"));
        assertThat(advisory.getSeverity(), notNullValue());
        assertThat(advisory.getVulnerableVersions(), notNullValue());
        assertThat(advisory.getCvssV3(), notNullValue());
    }

    @Test
    void testParseSkipsStringViaEntries() throws JSONException {
        final NpmAuditV2Parser parser = new NpmAuditV2Parser();
        final JSONObject v2Json = new JSONObject()
                .put("auditReportVersion", 2)
                .put("vulnerabilities", new JSONObject()
                        .put("uglify-js", new JSONObject()
                                .put("name", "uglify-js")
                                .put("severity", "high")
                                .put("via", new JSONArray().put("uglify-js"))
                                .put("nodes", new JSONArray().put("node_modules/uglify-js"))));

        final List<Advisory> advisories = parser.parse(v2Json, new File("."));

        assertThat(advisories.size(), is(0));
    }

    @Test
    void testParseReturnsEmptyListWhenNoVulnerabilities() throws JSONException {
        final NpmAuditV2Parser parser = new NpmAuditV2Parser();
        final JSONObject v2Json = new JSONObject()
                .put("auditReportVersion", 2)
                .put("vulnerabilities", new JSONObject());

        final List<Advisory> advisories = parser.parse(v2Json, new File("."));

        assertThat(advisories.size(), is(0));
    }

    @Test
    void testParseHandlesMissingVulnerabilitiesKey() throws JSONException {
        final NpmAuditV2Parser parser = new NpmAuditV2Parser();
        final JSONObject v2Json = new JSONObject()
                .put("auditReportVersion", 2);

        final List<Advisory> advisories = parser.parse(v2Json, new File("."));

        assertThat(advisories.size(), is(0));
    }

    @Test
    void testExtractGhsaId() {
        assertThat(NpmAuditV2Parser.extractGhsaId("https://github.com/advisories/GHSA-34r7-q49f-h37c"),
                is("GHSA-34r7-q49f-h37c"));
        assertThat(NpmAuditV2Parser.extractGhsaId(null), nullValue());
        assertThat(NpmAuditV2Parser.extractGhsaId("https://github.com/advisories/"), nullValue());
    }
}
