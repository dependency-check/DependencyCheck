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
 * Copyright (c) 2026 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class NpmAuditParserTest extends BaseTest {

    @Test
    void testParseExtractsVersionWhenPathsAreEmptyAndMultipleAdvisoriesShareModule() {
        final String auditJson = "{\n"
                + "  \"advisories\": {\n"
                + "    \"1106913\": {\n"
                + "      \"findings\": [{\"version\": \"4.17.11\", \"paths\": []}],\n"
                + "      \"module_name\": \"lodash\",\n"
                + "      \"github_advisory_id\": \"GHSA-35jh-r3h4-6jhm\",\n"
                + "      \"vulnerable_versions\": \"<4.17.21\",\n"
                + "      \"severity\": \"high\",\n"
                + "      \"cwe\": [\"CWE-77\", \"CWE-94\"]\n"
                + "    },\n"
                + "    \"1106918\": {\n"
                + "      \"findings\": [{\"version\": \"4.17.11\", \"paths\": []}],\n"
                + "      \"module_name\": \"lodash\",\n"
                + "      \"github_advisory_id\": \"GHSA-jf85-cpcp-j695\",\n"
                + "      \"vulnerable_versions\": \"<4.17.12\",\n"
                + "      \"severity\": \"critical\",\n"
                + "      \"cwe\": [\"CWE-20\", \"CWE-1321\"]\n"
                + "    }\n"
                + "  }\n"
                + "}";

        final NpmAuditParser parser = new NpmAuditParser();
        final List<Advisory> advisories = parser.parse(new JSONObject(auditJson));

        assertEquals(2, advisories.size());
        for (Advisory advisory : advisories) {
            assertEquals("lodash", advisory.getModuleName());
            assertEquals("4.17.11", advisory.getVersion());
        }
    }

    @Test
    void testParseEmitsOneAdvisoryPerDistinctFindingVersion() {
        final String auditJson = "{\n"
                + "  \"advisories\": {\n"
                + "    \"1004319\": {\n"
                + "      \"findings\": [\n"
                + "        {\"version\": \"1.8.5\", \"paths\": [\".>braces\"]},\n"
                + "        {\"version\": \"2.0.0\", \"paths\": [\".>micromatch>braces\"]},\n"
                + "        {\"version\": \"1.8.5\", \"paths\": [\".>chokidar>braces\"]}\n"
                + "      ],\n"
                + "      \"module_name\": \"braces\",\n"
                + "      \"github_advisory_id\": \"GHSA-g95f-p29q-9xw4\",\n"
                + "      \"vulnerable_versions\": \"<2.3.1\",\n"
                + "      \"severity\": \"low\",\n"
                + "      \"cwe\": \"CWE-185\"\n"
                + "    }\n"
                + "  }\n"
                + "}";

        final NpmAuditParser parser = new NpmAuditParser();
        final List<Advisory> advisories = parser.parse(new JSONObject(auditJson));

        assertEquals(2, advisories.size());
        assertEquals("1.8.5", advisories.get(0).getVersion());
        assertEquals("2.0.0", advisories.get(1).getVersion());
        assertEquals(List.of("CWE-185"), advisories.get(0).getCwes());
        assertEquals(List.of("CWE-185"), advisories.get(1).getCwes());
    }

    @Test
    void testParseHandlesMissingFindingsGracefully() {
        final String auditJson = "{\n"
                + "  \"advisories\": {\n"
                + "    \"1\": {\n"
                + "      \"module_name\": \"lodash\",\n"
                + "      \"github_advisory_id\": \"GHSA-1111-2222-3333\",\n"
                + "      \"vulnerable_versions\": \"<4.17.21\",\n"
                + "      \"severity\": \"high\"\n"
                + "    }\n"
                + "  }\n"
                + "}";

        final NpmAuditParser parser = new NpmAuditParser();
        final List<Advisory> advisories = parser.parse(new JSONObject(auditJson));

        assertEquals(1, advisories.size());
        assertNull(advisories.get(0).getVersion());
    }
}
