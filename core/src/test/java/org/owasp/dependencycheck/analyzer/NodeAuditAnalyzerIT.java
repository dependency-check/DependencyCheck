package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class NodeAuditAnalyzerIT extends BaseTest {

    @Test
    void testAnalyzePackage() throws AnalysisException, InitializationException, InvalidSettingException {
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED));
        try (Engine engine = new Engine(getSettings())) {
            NodeAuditAnalyzer analyzer = new NodeAuditAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, "nodeaudit/package-lock.json"));
            analyzer.analyze(toScan, engine);
            boolean found = false;
            assertTrue(1 < engine.getDependencies().length, "More then 1 dependency should be identified");
            for (Dependency result : engine.getDependencies()) {
                if ("package-lock.json?uglify-js".equals(result.getFileName())) {
                    found = true;
                    assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("uglify-js"));
                    assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("uglify-js"));
                    assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("2.4.24"));
                    assertTrue(result.isVirtual());
                }
            }
            assertTrue(found, "Uglify was not found");
        }
    }

    @Test
    void testAnalyzeEmpty() throws AnalysisException, InitializationException, InvalidSettingException {
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED));
        try (Engine engine = new Engine(getSettings())) {
            NodeAuditAnalyzer analyzer = new NodeAuditAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nodeaudit/empty.json"));
            analyzer.analyze(result, engine);

            assertEquals(0, result.getEvidence(EvidenceType.VENDOR).size());
            assertEquals(0, result.getEvidence(EvidenceType.PRODUCT).size());
            assertEquals(0, result.getEvidence(EvidenceType.VERSION).size());
        }
    }

    @Test
    void testAnalyzePackageJsonInNodeModulesDirectory() throws AnalysisException, InitializationException, InvalidSettingException {
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED));
        try (Engine engine = new Engine(getSettings())) {
            NodeAuditAnalyzer analyzer = new NodeAuditAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, "nodejs/node_modules/dns-sync/package.json"));
            engine.addDependency(toScan);
            analyzer.analyze(toScan, engine);
            assertEquals(0, engine.getDependencies().length, "No dependencies should exist");
        }
    }

}
