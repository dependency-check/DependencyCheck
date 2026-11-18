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
        assertEquals(2, smallvec.getVulnerabilities().size());
        assertTrue(smallvec.getVulnerabilities().contains(cve));
        assertTrue(smallvec.getVulnerabilities().stream().anyMatch(v -> v.getName().equals("RUSTSEC-2021-0003")));
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
