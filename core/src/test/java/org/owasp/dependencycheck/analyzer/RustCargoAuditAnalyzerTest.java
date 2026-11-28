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
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.nio.file.Files;
import java.util.Collection;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RustCargoAuditAnalyzerTest {

    private final RustCargoAuditAnalyzer analyzer = new RustCargoAuditAnalyzer();
    private final Dependency lockfile = new Dependency(new File("Cargo.lock"));

    @Test
    void reportsOnlyVulnerableCrates() throws Exception {
        final CveDB database = mock(CveDB.class);
        final Vulnerability cve = new Vulnerability();
        cve.setName("CVE-2019-15551");
        cve.setSource(Vulnerability.Source.NVD);
        when(database.getVulnerability(cve.getName())).thenReturn(cve);
        final String report = Files.readString(BaseTest.getResourceAsFile(this, "cargo/audit.json").toPath());
        final Collection<Dependency> crates = analyzer.parseReport(report, lockfile, database);
        assertEquals(1, crates.size());
        final Dependency smallvec = crates.iterator().next();
        assertEquals("pkg:cargo/smallvec@0.6.9", smallvec.getPackagePath());
        assertEquals(3, smallvec.getVulnerabilities().size());
        assertTrue(smallvec.getVulnerabilities().contains(cve));
        assertTrue(cve.getReferences().stream().anyMatch(r -> r.getName().equals("RUSTSEC-2019-0009")));
        final Vulnerability rustsec = smallvec.getVulnerabilities().stream()
                .filter(v -> v.getName().equals("RUSTSEC-2021-0003")).findFirst().orElseThrow();
        assertEquals(Vulnerability.Source.RUSTSEC, rustsec.getSource());
        assertEquals(9.8, rustsec.getCvssV3().getCvssData().getBaseScore());
        assertTrue(rustsec.getDescription().startsWith("Buffer overflow in SmallVec::insert_many\n\n"));
    }

    @Test
    void acceptsAnAdvisoryWithoutCvss() throws Exception {
        final String report = "{\"vulnerabilities\":{\"list\":[{\"package\":{\"name\":\"a\",\"version\":\"1.0.0\"},"
                + "\"advisory\":{\"id\":\"RUSTSEC-2026-0001\",\"title\":\"t\",\"description\":\"d\",\"aliases\":[],\"cvss\":null}}]}}";
        final Vulnerability vulnerability = analyzer.parseReport(report, lockfile, null)
                .iterator().next().getVulnerabilities().iterator().next();
        assertNull(vulnerability.getCvssV3());
        assertEquals("UNKNOWN", vulnerability.getUnscoredSeverity());
    }

    @Test
    void acceptsACleanReport() throws Exception {
        assertTrue(analyzer.parseReport("{\"vulnerabilities\":{\"list\":[]},\"warnings\":{}}", lockfile, null).isEmpty());
    }

    @Test
    void rejectsAnIncompleteReport() {
        assertThrows(AnalysisException.class, () -> analyzer.parseReport("{}", lockfile, null));
        assertThrows(AnalysisException.class, () -> analyzer.parseReport("{\"vulnerabilities\":{\"list\":{}}}", lockfile, null));
    }
}
