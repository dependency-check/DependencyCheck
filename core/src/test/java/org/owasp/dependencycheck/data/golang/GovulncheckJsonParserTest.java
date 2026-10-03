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
 * Copyright (c) 2026 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.golang;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link GovulncheckJsonParser}.
 *
 * @author Srinivas Chippagiri
 */
class GovulncheckJsonParserTest {

    private GovulncheckResult findById(List<GovulncheckResult> results, String id) {
        return results.stream().filter(r -> id.equals(r.getId())).findFirst().orElse(null);
    }

    @Test
    void testProcess() throws Exception {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("golang/govulncheck.json")) {
            assertNotNull(in, "test resource golang/govulncheck.json was not found");
            final List<GovulncheckResult> results = GovulncheckJsonParser.process(in);

            // one result per advisory, despite the config/progress messages and the
            // duplicate (module-level and symbol-level) findings for GO-2022-0969
            assertEquals(2, results.size());

            final GovulncheckResult called = findById(results, "GO-2022-0969");
            assertNotNull(called);
            assertEquals("golang.org/x/net", called.getModuleName());
            // leading "v" is stripped from module and fixed versions
            assertEquals("0.1.0", called.getModuleVersion());
            assertEquals("0.4.0", called.getFixedVersion());
            // the more precise (symbol-resolving) finding is retained
            assertTrue(called.isCalled());
            assertEquals("canonicalHeader", called.getSymbol());
            assertEquals("golang.org/x/net/http2", called.getPackageName());
            assertTrue(called.getAliases().contains("CVE-2022-41717"));
            assertTrue(called.getAliases().contains("GHSA-xrjj-mj9h-534m"));
            assertEquals(2, called.getReferences().size());

            final GovulncheckResult informational = findById(results, "GO-2021-0113");
            assertNotNull(informational);
            assertEquals("golang.org/x/text", informational.getModuleName());
            assertEquals("0.3.5", informational.getModuleVersion());
            assertEquals("0.3.7", informational.getFixedVersion());
            // module is present but no vulnerable symbol is reported as called
            assertFalse(informational.isCalled());
            assertNull(informational.getSymbol());
            assertTrue(informational.getAliases().contains("CVE-2021-38561"));
        }
    }
}
