package org.owasp.dependencycheck.data.nvdcve;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.NvdCveAnalyzer;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.values.Part;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * https://nvd.nist.gov/vuln/detail/CVE-2024-35255
 * https://nvd.nist.gov/vuln/detail/CVE-2023-36415
 * https://github.com/dependency-check/DependencyCheck/issues/5992
 * https://github.com/dependency-check/DependencyCheck/issues/7139
 * https://github.com/dependency-check/DependencyCheck/pull/8852
 */
class CveMatchingBehaviourTest {

    private static final class ExposedNvdCveAnalyzer extends NvdCveAnalyzer {
        void run(Dependency dependency, Engine engine) throws Exception {
            analyzeDependency(dependency, engine);
        }
    }

    private static CpeIdentifier id(String vendor, String product, String version) throws Exception {
        return new CpeIdentifier(vendor, product, version, Confidence.HIGHEST);
    }

    private static VulnerableSoftware until(String vendor, String product,
            String targetSw, String versionEndExcluding) throws Exception {
        VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder()
                .part(Part.APPLICATION).vendor(vendor).product(product)
                .version("*").update("*").targetSw(targetSw).vulnerable(true);
        builder.versionEndExcluding(versionEndExcluding);
        return builder.build();
    }

    private static VulnerableSoftware fromUntil(String vendor, String product,
            String targetSw, String versionStartIncluding, String versionEndExcluding) throws Exception {
        VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder()
                .part(Part.APPLICATION).vendor(vendor).product(product)
                .version("*").update("*").targetSw(targetSw).vulnerable(true);
        builder.versionStartIncluding(versionStartIncluding);
        builder.versionEndExcluding(versionEndExcluding);
        return builder.build();
    }

    private static VulnerableSoftware through(String vendor, String product,
            String targetSw, String versionEndIncluding) throws Exception {
        VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder()
                .part(Part.APPLICATION).vendor(vendor).product(product)
                .version("*").update("*").targetSw(targetSw).vulnerable(true);
        builder.versionEndIncluding(versionEndIncluding);
        return builder.build();
    }

    private static Vulnerability candidate(String name, VulnerableSoftware selected,
            VulnerableSoftware... entries) {
        Vulnerability result = new Vulnerability(name);
        result.setSource(Vulnerability.Source.NVD);
        for (VulnerableSoftware entry : entries) {
            result.addVulnerableSoftware(entry);
        }
        result.setMatchedVulnerableSoftware(selected);
        return result;
    }

    private static Dependency analyze(CveDB db, CpeIdentifier identifier, String ecosystem)
            throws Exception {
        Engine engine = mock(Engine.class);
        when(engine.getDatabase()).thenReturn(db);
        Dependency dependency = new Dependency(true);
        dependency.setEcosystem(ecosystem);
        dependency.addVulnerableSoftwareIdentifier(identifier);
        new ExposedNvdCveAnalyzer().run(dependency, engine);
        return dependency;
    }

    private static CveDB dbReturning(List<Vulnerability> sharedCacheEntry) {
        CveDB db = mock(CveDB.class);
        when(db.getVulnerabilities(any(Cpe.class))).thenReturn(sharedCacheEntry);
        return db;
    }

    @Test
    void microsoftAuthenticationLibrarySelectionShouldNotDependOnSetIterationOrder() throws Exception {
        Cpe cpe = id("microsoft", "authentication_library", "1.8.0").getCpe();
        VulnerableSoftware java = until("microsoft", "authentication_library", "java", "1.15.1");
        VulnerableSoftware node = through("microsoft", "authentication_library", "node.js", "2.9.2");
        assertTrue(java.matches(cpe));
        assertTrue(node.matches(cpe));

        Set<VulnerableSoftware> javaFirst = new LinkedHashSet<>(Arrays.asList(java, node));
        Set<VulnerableSoftware> nodeFirst = new LinkedHashSet<>(Arrays.asList(node, java));
        assertEquals(2, javaFirst.size());
        assertEquals(2, nodeFirst.size());

        CveDB db = mock(CveDB.class, CALLS_REAL_METHODS);
        assertSame(db.getMatchingSoftware(cpe, javaFirst),
                db.getMatchingSoftware(cpe, nodeFirst),
                "Same matching NVD rows should not give different attribution by iteration order");
    }

    @Test
    void microsoftMultiRuntimeCveShouldNotRetainStaleMatchedSoftware() throws Exception {
        CpeIdentifier identifier = id("microsoft", "authentication_library", "1.8.0");
        VulnerableSoftware java = until("microsoft", "authentication_library", "java", "1.15.1");
        VulnerableSoftware node = through("microsoft", "authentication_library", "node.js", "2.9.2");
        assertTrue(java.matches(identifier.getCpe()));
        assertTrue(node.matches(identifier.getCpe()));

        CveDB matcher = mock(CveDB.class, CALLS_REAL_METHODS);
        VulnerableSoftware initial = matcher.getMatchingSoftware(identifier.getCpe(),
                new LinkedHashSet<>(Arrays.asList(java, node)));
        assertSame(java, initial);
        Vulnerability v = candidate("CVE-2024-35255", initial, java, node);
        Dependency reported = analyze(dbReturning(new ArrayList<>(List.of(v))), identifier,
                Ecosystem.NODEJS);

        assertEquals(1, reported.getVulnerabilities().size());
        Vulnerability actual = reported.getVulnerabilities().iterator().next();
        assertTrue(actual.getVulnerableSoftware().contains(node),
                "Node.js CPE alternative must survive the Node ecosystem filter");
        assertTrue(actual.getVulnerableSoftware().contains(actual.getMatchedVulnerableSoftware()),
                "The matched row must refer to a retained entry after filtering");
        assertTrue(actual.getMatchedVulnerableSoftware().matches(identifier.getCpe()),
                "Retained attribution must also match the dependency CPE");
    }

    @Test
    void unrelatedProductMustNotKeepCveAfterTheOnlyMatchingRowIsFiltered() throws Exception {
        CpeIdentifier identifier = id("microsoft", "azure_identity_sdk", "1.8.0");
        VulnerableSoftware python = until("microsoft", "azure_identity_sdk", "python", "1.16.1");
        VulnerableSoftware otherProductNode = through("microsoft", "authentication_library",
                "node.js", "2.9.2");
        assertTrue(python.matches(identifier.getCpe()));
        assertFalse(otherProductNode.matches(identifier.getCpe()));

        CveDB matcher = mock(CveDB.class, CALLS_REAL_METHODS);
        VulnerableSoftware initial = matcher.getMatchingSoftware(identifier.getCpe(),
                new LinkedHashSet<>(List.of(python)));
        assertSame(python, initial);
        Vulnerability v = candidate("CVE-TEST-CROSS-PRODUCT", initial,
                python, otherProductNode);
        Dependency reported = analyze(dbReturning(new ArrayList<>(List.of(v))), identifier,
                Ecosystem.NODEJS);

        assertTrue(reported.getVulnerabilities().isEmpty(),
                "There is no software entry matching BOTH this CPE and this ecosystem");
    }

    @Test
    void azureIdentityJava1103MustNotInheritPythonVulnerableRange() throws Exception {
        CpeIdentifier javaIdentifier = id("microsoft", "azure_identity_sdk", "1.10.3");
        Cpe cpe = javaIdentifier.getCpe();
        VulnerableSoftware java = until("microsoft", "azure_identity_sdk", "java", "1.10.2");
        VulnerableSoftware python = until("microsoft", "azure_identity_sdk", "python", "1.14.1");
        VulnerableSoftware javascript = fromUntil("microsoft", "azure_identity_sdk", "javascript", "3.0.0", "3.3.1");
        VulnerableSoftware dotNet = until("microsoft", "azure_identity_sdk", ".net", "1.10.2");

        assertFalse(java.matches(cpe), "Java 1.10.3 is outside the Java affected range");
        assertTrue(python.matches(cpe), "The unscoped CPE would match the Python range");
        CveDB matcher = mock(CveDB.class, CALLS_REAL_METHODS);
        VulnerableSoftware wronglyMatched = matcher.getMatchingSoftware(cpe,
                new LinkedHashSet<>(Arrays.asList(java, python, javascript, dotNet)));
        assertNotNull(wronglyMatched,
                "Characterization: today's CPE-only matcher admits this CVE via another runtime");
        Vulnerability candidate = candidate("CVE-2023-36415", wronglyMatched,
                java, python, javascript, dotNet);

        Dependency reported = analyze(dbReturning(new ArrayList<>(List.of(candidate))),
                javaIdentifier, Ecosystem.JAVA);
        assertTrue(reported.getVulnerabilities().isEmpty(),
                "The real azure-identity:1.10.3 Java package must not inherit a Python/JS version range");
    }

    @Test
    void nodeAnalysisMustNotPoisonCachedResultsNeededByJavaAnalysis() throws Exception {
        CpeIdentifier identifier = id("microsoft", "azure_identity_sdk", "1.0.0");
        VulnerableSoftware java = until("microsoft", "azure_identity_sdk", "java", "1.10.2");
        VulnerableSoftware python = until("microsoft", "azure_identity_sdk", "python", "1.14.1");
        VulnerableSoftware javascript = fromUntil("microsoft", "azure_identity_sdk", "javascript", "3.0.0", "3.3.1");
        VulnerableSoftware dotNet = until("microsoft", "azure_identity_sdk", ".net", "1.10.2");
        Vulnerability shared = candidate("CVE-2023-36415", java,
                java, python, javascript, dotNet);
        List<Vulnerability> cacheEntry = new ArrayList<>(List.of(shared));
        CveDB db = dbReturning(cacheEntry);

        analyze(db, identifier, Ecosystem.NODEJS);
        Dependency javaAfterNode = analyze(db, identifier, Ecosystem.JAVA);

        assertEquals(1, javaAfterNode.getVulnerabilities().size(),
                "A Node.js scan must not erase an applicable Java CVE from shared CveDB results");
        assertEquals(1, cacheEntry.size(),
                "Filtering must not remove a CVE from a cache-owned collection");
        assertEquals(4, shared.getVulnerableSoftware().size(),
                "Filtering must not remove CPE alternatives from cache-owned vulnerability objects");
    }
}
