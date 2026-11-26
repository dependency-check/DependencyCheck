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
import org.owasp.dependencycheck.dependency.Vulnerability;
import us.springett.parsers.cpe.exceptions.CpeValidationException;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PnpmAuditAnalyzerTest extends BaseTest
{

    @Test
    void testNpmAuditParserCompatibility() throws IOException, JSONException
    {
        NpmAuditParser npmAuditParser = new NpmAuditParser();
        JSONObject vulnsAuditJson = new JSONObject(IOUtils.toString(getResourceAsStream(this, "pnpmaudit/pnpm-audit.json"), StandardCharsets.UTF_8));
        List<Advisory> advisories = npmAuditParser.parse(vulnsAuditJson);
        assertThat(advisories.size(), is(2));
        assertThat(advisories.get(0).getModuleName(), is("dns-sync"));
        assertThat(advisories.get(0).getVersion(), is("0.1.3"));
        assertThat(advisories.get(0).getCwes(), is(List.of("CWE-94")));
        assertThat(advisories.get(1).getModuleName(), is("braces"));
        assertThat(advisories.get(1).getVersion(), is("1.8.5"));
        assertThat(advisories.get(1).getCwes(), is(List.of("CWE-185")));
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
    void testProcessResultsPreservesMultipleAdvisoriesWhenPathsEmptyAndWhenVersionIsNull() throws CpeValidationException {
        final String auditJson = "{\n"
                + "  \"advisories\": {\n"
                + "    \"1106913\": {\n"
                + "      \"findings\": [{\"version\": \"4.17.11\", \"paths\": []}],\n"
                + "      \"module_name\": \"lodash\",\n"
                + "      \"github_advisory_id\": \"GHSA-35jh-r3h4-6jhm\",\n"
                + "      \"vulnerable_versions\": \"<4.17.21\",\n"
                + "      \"severity\": \"high\"\n"
                + "    },\n"
                + "    \"1106918\": {\n"
                + "      \"findings\": [{\"version\": \"4.17.11\", \"paths\": []}],\n"
                + "      \"module_name\": \"lodash\",\n"
                + "      \"github_advisory_id\": \"GHSA-jf85-cpcp-j695\",\n"
                + "      \"vulnerable_versions\": \"<4.17.12\",\n"
                + "      \"severity\": \"critical\"\n"
                + "    },\n"
                + "    \"1106920\": {\n"
                + "      \"findings\": [{\"version\": \"4.17.11\", \"paths\": []}],\n"
                + "      \"module_name\": \"lodash\",\n"
                + "      \"github_advisory_id\": \"GHSA-p6mc-m468-83gw\",\n"
                + "      \"vulnerable_versions\": \">=3.7.0 <4.17.19\",\n"
                + "      \"severity\": \"high\"\n"
                + "    }\n"
                + "  }\n"
                + "}";
        final List<Advisory> advisories = new NpmAuditParser().parse(new JSONObject(auditJson));
        final PnpmAuditAnalyzer analyzer = new PnpmAuditAnalyzer();
        final Dependency lockDependency = new Dependency(new File("pnpm-lock.yaml"));
        final MultiValuedMap<String, String> emptyMap = new HashSetValuedHashMap<>();

        try (Engine engine = new Engine(getSettings())) {
            analyzer.processResults(advisories, engine, lockDependency, emptyMap);
            assertEquals(1, engine.getDependencies().length);
            final Dependency lodash = engine.getDependencies()[0];
            assertEquals("lodash", lodash.getName());
            assertEquals("4.17.11", lodash.getVersion());
            final Set<String> vulnNames = lodash.getVulnerabilities().stream()
                    .map(Vulnerability::getName)
                    .collect(Collectors.toSet());
            assertEquals(Set.of("GHSA-35jh-r3h4-6jhm", "GHSA-jf85-cpcp-j695", "GHSA-p6mc-m468-83gw"), vulnNames);
        }

        // Also verify multiple advisories with null version do not drop vulnerabilities
        final Advisory nullVer1 = new Advisory();
        nullVer1.setGhsaId("GHSA-aaaa-bbbb-cccc");
        nullVer1.setModuleName("lodash");
        nullVer1.setVulnerableVersions("<4.17.21");
        nullVer1.setSeverity("high");
        nullVer1.setCwes(List.of());
        final Advisory nullVer2 = new Advisory();
        nullVer2.setGhsaId("GHSA-dddd-eeee-ffff");
        nullVer2.setModuleName("lodash");
        nullVer2.setVulnerableVersions("<4.17.12");
        nullVer2.setSeverity("critical");
        nullVer2.setCwes(List.of());

        try (Engine engine = new Engine(getSettings())) {
            analyzer.processResults(List.of(nullVer1, nullVer2), engine, lockDependency, emptyMap);
            assertEquals(1, engine.getDependencies().length);
            final Dependency lodash = engine.getDependencies()[0];
            final Set<String> vulnNames = lodash.getVulnerabilities().stream()
                    .map(Vulnerability::getName)
                    .collect(Collectors.toSet());
            assertEquals(Set.of("GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"), vulnNames);
        }
    }

    @Test
    void testBuildDependencyMapSupportsLockfileVersionsAndFallback(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tempDir)
            throws IOException, CpeValidationException {
        final PnpmAuditAnalyzer analyzer = new PnpmAuditAnalyzer();
        final File v5Lock = BaseTest.getResourceAsFile(this, "pnpmaudit/pnpm-lock.yaml");
        final MultiValuedMap<String, String> v5Map = analyzer.buildDependencyMap(v5Lock, false);
        assertThat(v5Map.get("braces").contains("1.8.5"), is(true));
        assertThat(v5Map.get("@hot-loader/react-dom").contains("17.0.1"), is(true));
        assertThat(v5Map.get("kind-of").containsAll(List.of("3.2.2", "6.0.3")), is(true));

        final File v6Lock = tempDir.resolve("pnpm-lock-v6.yaml").toFile();
        java.nio.file.Files.writeString(v6Lock.toPath(),
                "lockfileVersion: '6.0'\n"
                        + "packages:\n"
                        + "  /lodash@4.17.11:\n"
                        + "    dev: false\n"
                        + "  /@scope/pkg@1.2.3(react@18.2.0):\n"
                        + "    dev: true\n"
                        + "  /@my_scope/my_pkg/2.0.0_react@18.2.0:\n"
                        + "    dev: false\n",
                StandardCharsets.UTF_8);
        final MultiValuedMap<String, String> v6All = analyzer.buildDependencyMap(v6Lock, false);
        assertThat(v6All.get("lodash").contains("4.17.11"), is(true));
        assertThat(v6All.get("@scope/pkg").contains("1.2.3"), is(true));
        assertThat(v6All.get("@my_scope/my_pkg").contains("2.0.0"), is(true));

        final MultiValuedMap<String, String> v6Prod = analyzer.buildDependencyMap(v6Lock, true);
        assertThat(v6Prod.get("lodash").contains("4.17.11"), is(true));
        assertThat(v6Prod.containsKey("@scope/pkg"), is(false));

        final File v9Lock = tempDir.resolve("pnpm-lock-v9.yaml").toFile();
        java.nio.file.Files.writeString(v9Lock.toPath(),
                "lockfileVersion: '9.0'\n"
                        + "packages:\n"
                        + "  lodash@4.17.11:\n"
                        + "    resolution: {integrity: sha512-test}\n"
                        + "  '@scope/lib@3.1.4':\n"
                        + "    resolution: {integrity: sha512-test2}\n",
                StandardCharsets.UTF_8);
        final MultiValuedMap<String, String> v9Map = analyzer.buildDependencyMap(v9Lock, false);
        assertThat(v9Map.get("lodash").contains("4.17.11"), is(true));
        assertThat(v9Map.get("@scope/lib").contains("3.1.4"), is(true));

        // Verify fallback version resolution via dependencyMap when advisory has null version
        final Advisory noVersionAdvisory = new Advisory();
        noVersionAdvisory.setGhsaId("GHSA-35jh-r3h4-6jhm");
        noVersionAdvisory.setModuleName("lodash");
        noVersionAdvisory.setVulnerableVersions("<4.17.21");
        noVersionAdvisory.setSeverity("high");
        try (Engine engine = new Engine(getSettings())) {
            analyzer.processResults(List.of(noVersionAdvisory), engine, new Dependency(v9Lock), v9Map);
            assertEquals(1, engine.getDependencies().length);
            assertEquals("4.17.11", engine.getDependencies()[0].getVersion());
        }
    }
}
