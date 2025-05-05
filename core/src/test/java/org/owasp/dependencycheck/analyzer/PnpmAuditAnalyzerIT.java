package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class PnpmAuditAnalyzerIT extends BaseTest {

    @Test
    @Disabled("unfortunately pnpm and brew are somewhat broken on my machine atm...")
    void testAnalyzePackagePnpm() throws AnalysisException {

        try (Engine engine = new Engine(getSettings())) {
            PnpmAuditAnalyzer analyzer = new PnpmAuditAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            analyzer.setEnabled(true);
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, "pnpmaudit/pnpm-lock.yaml"));
            analyzer.analyze(toScan, engine);
            boolean found = false;
            assertTrue(1 < engine.getDependencies().length, "More than 1 dependency should be identified");
            for (Dependency result : engine.getDependencies()) {
                if ("pnpm-lock.yaml?dns-sync".equals(result.getFileName())) {
                    found = true;
                    assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("dns-sync"));
                    assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("dns-sync"));
                    assertTrue(result.isVirtual());
                }
            }
            assertTrue(found, "dns-sync was not found");
        } catch (InitializationException ex) {
            //yarn is not installed - skip the test case.
            assumeTrue(false, ex.toString());
        }
    }
}
