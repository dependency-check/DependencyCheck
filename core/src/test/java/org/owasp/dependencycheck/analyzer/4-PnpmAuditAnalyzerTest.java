package org.owasp.dependencycheck.analyzer;

import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.apache.commons.io.IOUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.data.nodeaudit.NpmAuditParser;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

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

    @Test
    void testNpmAuditParserSetsVersionFromPnpmStylePaths() throws IOException, JSONException
    {
        NpmAuditParser npmAuditParser = new NpmAuditParser();
        JSONObject vulnsAuditJson = new JSONObject(IOUtils.toString(getResourceAsStream(this, "pnpmaudit/pnpm-audit.json"), StandardCharsets.UTF_8));
        List<Advisory> advisories = npmAuditParser.parse(vulnsAuditJson);
        assertThat(advisories.size(), is(2));
        for (Advisory advisory : advisories) {
            if ("dns-sync".equals(advisory.getModuleName())) {
                assertThat(advisory.getVersion(), is("0.1.3"));
            } else if ("braces".equals(advisory.getModuleName())) {
                assertThat(advisory.getVersion(), is("1.8.5"));
            }
        }
    }

    @Test
    void testNpmAuditParserSetsVersionFromFindingsWhenPathsAreEmpty() throws IOException, JSONException
    {
        // pnpm 9 emits findings with empty paths arrays; the installed version must still be detected
        NpmAuditParser npmAuditParser = new NpmAuditParser();
        JSONObject vulnsAuditJson = new JSONObject(IOUtils.toString(getResourceAsStream(this, "pnpmaudit/pnpm-audit-v9.json"), StandardCharsets.UTF_8));
        List<Advisory> advisories = npmAuditParser.parse(vulnsAuditJson);
        assertThat(advisories.size(), is(2));
        assertThat(advisories.get(0).getVersion(), is("2.1.2"));
        assertThat(advisories.get(1).getVersion(), is("2.1.2"));
    }

    @Test
    void testPackageNameAndVersionFromLockKey()
    {
        // classic lockfile format (lockfileVersion 5.x/6.x)
        assertThat(PnpmAuditAnalyzer.packageNameFromLockKey("/braces/1.8.5"), is("braces"));
        assertThat(PnpmAuditAnalyzer.packageVersionFromLockKey("/braces/1.8.5"), is("1.8.5"));
        assertThat(PnpmAuditAnalyzer.packageNameFromLockKey("/@hot-loader/react-dom/17.0.1"), is("@hot-loader/react-dom"));
        assertThat(PnpmAuditAnalyzer.packageVersionFromLockKey("/@hot-loader/react-dom/17.0.1"), is("17.0.1"));
        assertThat(PnpmAuditAnalyzer.packageNameFromLockKey("/react-dom/17.0.1_react@17.0.1"), is("react-dom"));
        assertThat(PnpmAuditAnalyzer.packageVersionFromLockKey("/react-dom/17.0.1_react@17.0.1"), is("17.0.1"));
        // modern lockfile format (lockfileVersion 9+)
        assertThat(PnpmAuditAnalyzer.packageNameFromLockKey("brace-expansion@2.1.2"), is("brace-expansion"));
        assertThat(PnpmAuditAnalyzer.packageVersionFromLockKey("brace-expansion@2.1.2"), is("2.1.2"));
        assertThat(PnpmAuditAnalyzer.packageNameFromLockKey("@hot-loader/react-dom@17.0.1"), is("@hot-loader/react-dom"));
        assertThat(PnpmAuditAnalyzer.packageVersionFromLockKey("@hot-loader/react-dom@17.0.1"), is("17.0.1"));
        assertThat(PnpmAuditAnalyzer.packageNameFromLockKey("react-dom@17.0.1(react@17.0.1)"), is("react-dom"));
        assertThat(PnpmAuditAnalyzer.packageVersionFromLockKey("react-dom@17.0.1(react@17.0.1)"), is("17.0.1"));
    }

    @Test
    void testCollectInstalledVersionsFromClassicLockFile() throws IOException
    {
        File lockFile = new File("src/test/resources/pnpmaudit/pnpm-lock.yaml");
        MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        PnpmAuditAnalyzer.collectInstalledVersions(lockFile, dependencyMap);
        assertThat(dependencyMap.get("braces").contains("1.8.5"), is(true));
        assertThat(dependencyMap.get("dns-sync").contains("0.1.3"), is(true));
        assertThat(dependencyMap.get("@hot-loader/react-dom").contains("17.0.1"), is(true));
    }

    @Test
    void testCollectInstalledVersionsFromModernLockFile() throws IOException
    {
        File lockFile = new File("src/test/resources/pnpmaudit/pnpm-lock-v9.yaml");
        MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        PnpmAuditAnalyzer.collectInstalledVersions(lockFile, dependencyMap);
        assertThat(dependencyMap.get("brace-expansion").contains("2.1.2"), is(true));
        assertThat(dependencyMap.get("moment").contains("2.29.4"), is(true));
    }

    @Test
    void testProcessResultsDoesNotDropAdvisoriesForSamePackage() throws Exception
    {
        // regression test for dependency-check/DependencyCheck#8846: multiple advisories for one
        // pnpm package must all be reported instead of being silently discarded on merge
        NpmAuditParser npmAuditParser = new NpmAuditParser();
        JSONObject vulnsAuditJson = new JSONObject(IOUtils.toString(getResourceAsStream(this, "pnpmaudit/pnpm-audit-v9.json"), StandardCharsets.UTF_8));
        List<Advisory> advisories = npmAuditParser.parse(vulnsAuditJson);
        assertThat(advisories.size(), is(2));

        MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        PnpmAuditAnalyzer.collectInstalledVersions(new File("src/test/resources/pnpmaudit/pnpm-lock-v9.yaml"), dependencyMap);

        PnpmAuditAnalyzer analyzer = new PnpmAuditAnalyzer();
        try (Engine engine = new Engine(getSettings())) {
            Dependency lockDependency = new Dependency(new File("src/test/resources/pnpmaudit/pnpm-lock-v9.yaml"), true);
            analyzer.processResults(advisories, engine, lockDependency, dependencyMap);

            List<Dependency> matches = Arrays.stream(engine.getDependencies())
                    .filter(d -> "brace-expansion".equals(d.getName()))
                    .collect(Collectors.toList());
            assertThat(matches.size(), is(1));
            assertThat(matches.get(0).getVersion(), is("2.1.2"));
            assertThat(matches.get(0).getVulnerabilities().size(), is(2));
        }
    }

    @Test
    void testProcessResultsSeparatesAdvisoriesAcrossInstalledVersions() throws Exception
    {
        // two advisories for the same module affecting two different installed versions must
        // produce two dependencies with the correct versions, never one collapsed entry
        Advisory first = buildAdvisory("GHSA-0000-0000-0001", "brace-expansion", "1.5.0", "<1.5.1");
        Advisory second = buildAdvisory("GHSA-0000-0000-0002", "brace-expansion", "2.0.1", ">=2.0.0 <2.0.2");

        MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        dependencyMap.put("brace-expansion", "1.5.0");
        dependencyMap.put("brace-expansion", "2.0.1");

        PnpmAuditAnalyzer analyzer = new PnpmAuditAnalyzer();
        try (Engine engine = new Engine(getSettings())) {
            Dependency lockDependency = new Dependency(new File("src/test/resources/pnpmaudit/pnpm-lock-v9.yaml"), true);
            analyzer.processResults(Arrays.asList(first, second), engine, lockDependency, dependencyMap);

            List<Dependency> matches = Arrays.stream(engine.getDependencies())
                    .filter(d -> "brace-expansion".equals(d.getName()))
                    .collect(Collectors.toList());
            assertThat(matches.size(), is(2));
            for (Dependency d : matches) {
                assertThat(d.getVulnerabilities().size(), is(1));
                if ("1.5.0".equals(d.getVersion())) {
                    assertThat(d.getVulnerabilities().iterator().next().getName(), is("GHSA-0000-0000-0001"));
                } else {
                    assertThat(d.getVersion(), is("2.0.1"));
                    assertThat(d.getVulnerabilities().iterator().next().getName(), is("GHSA-0000-0000-0002"));
                }
            }
        }
    }

    @Test
    void testAmbiguousFindingsAreResolvedFromTheDependencyMap() throws Exception
    {
        // when the findings do not identify a single installed version, the version must be
        // resolved from the lock file map using the vulnerable range - never guessed
        Advisory advisory = buildAdvisory("GHSA-0000-0000-0003", "brace-expansion", null, ">=2.0.0 <2.1.3");

        MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        dependencyMap.put("brace-expansion", "1.5.0");
        dependencyMap.put("brace-expansion", "2.1.2");

        PnpmAuditAnalyzer analyzer = new PnpmAuditAnalyzer();
        try (Engine engine = new Engine(getSettings())) {
            Dependency lockDependency = new Dependency(new File("src/test/resources/pnpmaudit/pnpm-lock-v9.yaml"), true);
            analyzer.processResults(List.of(advisory), engine, lockDependency, dependencyMap);

            List<Dependency> matches = Arrays.stream(engine.getDependencies())
                    .filter(d -> "brace-expansion".equals(d.getName()))
                    .collect(Collectors.toList());
            assertThat(matches.size(), is(1));
            assertThat(matches.get(0).getVersion(), is("2.1.2"));
        }
    }

    @Test
    void testCollectInstalledVersionsRejectsMalformedLockFile() throws IOException
    {
        File malformed = File.createTempFile("pnpm-lock-malformed", ".yaml");
        malformed.deleteOnExit();
        java.nio.file.Files.writeString(malformed.toPath(), "packages:\n  'unclosed: [");
        try {
            PnpmAuditAnalyzer.collectInstalledVersions(malformed, new HashSetValuedHashMap<>());
            org.junit.jupiter.api.Assertions.fail("malformed lock file must raise IOException so the caller can fall back");
        } catch (IOException expected) {
            // expected: the analyzer falls back to findings-only version detection with a warning
        }
    }

    private static Advisory buildAdvisory(String ghsaId, String moduleName, String version, String vulnerableVersions)
    {
        Advisory advisory = new Advisory();
        advisory.setGhsaId(ghsaId);
        advisory.setModuleName(moduleName);
        advisory.setVersion(version);
        advisory.setVulnerableVersions(vulnerableVersions);
        advisory.setSeverity("high");
        advisory.setOverview("test advisory " + ghsaId);
        advisory.setCwes(List.of());
        advisory.setReferences("");
        return advisory;
    }

    @Test
    void testProcessResultsDoesNotDropAdvisoriesWhenVersionUndetectable() throws Exception
    {
        // even if no installed version can be determined, additional advisories for the same
        // package must be attached to the same virtual dependency instead of being merged away
        NpmAuditParser npmAuditParser = new NpmAuditParser();
        JSONObject vulnsAuditJson = new JSONObject(IOUtils.toString(getResourceAsStream(this, "pnpmaudit/pnpm-audit-v9.json"), StandardCharsets.UTF_8));
        List<Advisory> advisories = npmAuditParser.parse(vulnsAuditJson);
        advisories.forEach(a -> a.setVersion(null));

        PnpmAuditAnalyzer analyzer = new PnpmAuditAnalyzer();
        try (Engine engine = new Engine(getSettings())) {
            Dependency lockDependency = new Dependency(new File("src/test/resources/pnpmaudit/pnpm-lock-v9.yaml"), true);
            analyzer.processResults(advisories, engine, lockDependency, new HashSetValuedHashMap<>());

            List<Dependency> matches = Arrays.stream(engine.getDependencies())
                    .filter(d -> "brace-expansion".equals(d.getName()))
                    .collect(Collectors.toList());
            assertThat(matches.size(), is(1));
            assertThat(matches.get(0).getVulnerabilities().size(), is(2));
        }
    }
}
