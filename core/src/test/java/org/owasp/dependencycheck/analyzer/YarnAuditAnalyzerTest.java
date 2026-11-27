package org.owasp.dependencycheck.analyzer;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;

import java.io.File;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;

class YarnAuditAnalyzerTest extends BaseTest {

    /**
     * Shaped like a single line of `yarn npm audit --all --recursive --no-deprecations --json`
     * output, with two installed versions of the vulnerable module in the dependency tree.
     */
    private static final String UUID_MULTI_VERSION_ADVISORY = "{\"value\":\"uuid\",\"children\":{"
            + "\"ID\":1119441,"
            + "\"Issue\":\"uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided\","
            + "\"URL\":\"https://github.com/advisories/GHSA-w5hq-g745-h8pq\","
            + "\"Severity\":\"moderate\","
            + "\"Vulnerable Versions\":\"<11.1.1\","
            + "\"Tree Versions\":[\"3.3.2\",\"8.3.1\"],"
            + "\"Dependents\":[\"@ti8m/workbench-widget-loader@workspace:.\"]}}";

    /**
     * A second advisory with two installed versions, used to verify that advisories do not
     * leak versions into each other.
     */
    private static final String LODASH_MULTI_VERSION_ADVISORY = "{\"value\":\"lodash\",\"children\":{"
            + "\"ID\":1525674,"
            + "\"Issue\":\"lodash: Command injection via template\","
            + "\"URL\":\"https://github.com/advisories/GHSA-35jh-r3h4-6jhm\","
            + "\"Severity\":\"high\","
            + "\"Vulnerable Versions\":\"<4.17.19\","
            + "\"Tree Versions\":[\"4.17.18\",\"4.17.21\"],"
            + "\"Dependents\":[\"left-pad@workspace:.\"]}}";

    @Test
    void testGetName() {
        YarnAuditAnalyzer analyzer = new YarnAuditAnalyzer();
        assertThat(analyzer.getName(), is("Yarn Audit Analyzer"));
    }

    @Test
    void testSupportsFiles() {
        YarnAuditAnalyzer analyzer = new YarnAuditAnalyzer();
        assertThat(analyzer.accept(new File("package-lock.json")), is(false));
        assertThat(analyzer.accept(new File("npm-shrinkwrap.json")), is(false));
        assertThat(analyzer.accept(new File("yarn.lock")), is(true));
        assertThat(analyzer.accept(new File("package.json")), is(false));
    }

    @Test
    void testParseAdvisoryJsonsCreatesOneAdvisoryPerTreeVersion() throws Exception {
        final List<Advisory> advisories = parseAdvisories(UUID_MULTI_VERSION_ADVISORY);

        assertEquals(2, advisories.size());
        assertNotSame(advisories.get(0), advisories.get(1));
        assertEquals(Set.of("3.3.2", "8.3.1"), versionsOf(advisories));
        for (Advisory advisory : advisories) {
            assertEquals("GHSA-w5hq-g745-h8pq", advisory.getGhsaId());
            assertEquals("uuid", advisory.getModuleName());
            assertEquals("moderate", advisory.getSeverity());
            assertEquals("<11.1.1", advisory.getVulnerableVersions());
            assertEquals("uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided", advisory.getTitle());
            assertEquals("URL:https://github.com/advisories/GHSA-w5hq-g745-h8pqID: 1119441", advisory.getOverview());
            assertEquals(0, advisory.getCwes().size());
        }
    }

    @Test
    void testParseAdvisoryJsonsSingleTreeVersion() throws Exception {
        final String single = UUID_MULTI_VERSION_ADVISORY.replace("[\"3.3.2\",\"8.3.1\"]", "[\"4.17.21\"]");
        final List<Advisory> advisories = parseAdvisories(single);

        assertEquals(1, advisories.size());
        assertEquals("4.17.21", advisories.get(0).getVersion());
    }

    @Test
    void testParseAdvisoryJsonsMissingTreeVersionsKeepsUnresolvedVersion() throws Exception {
        final String missing = UUID_MULTI_VERSION_ADVISORY.replace(",\"Tree Versions\":[\"3.3.2\",\"8.3.1\"]", "");
        final List<Advisory> advisories = parseAdvisories(missing);

        assertEquals(1, advisories.size());
        assertNull(advisories.get(0).getVersion());
    }

    @Test
    void testParseAdvisoryJsonsEmptyTreeVersionsKeepsUnresolvedVersion() throws Exception {
        final String empty = UUID_MULTI_VERSION_ADVISORY.replace("[\"3.3.2\",\"8.3.1\"]", "[]");
        final List<Advisory> advisories = parseAdvisories(empty);

        assertEquals(1, advisories.size());
        assertNull(advisories.get(0).getVersion());
    }

    @Test
    void testParseAdvisoryJsonsMultipleAdvisoriesDoNotShareVersions() throws Exception {
        final List<Advisory> advisories = parseAdvisories(UUID_MULTI_VERSION_ADVISORY, LODASH_MULTI_VERSION_ADVISORY);

        assertEquals(4, advisories.size());
        final Set<String> ghsaAndVersion = advisories.stream()
                .map(advisory -> advisory.getGhsaId() + "@" + advisory.getVersion())
                .collect(Collectors.toCollection(TreeSet::new));
        assertEquals(Set.of(
                "GHSA-w5hq-g745-h8pq@3.3.2",
                "GHSA-w5hq-g745-h8pq@8.3.1",
                "GHSA-35jh-r3h4-6jhm@4.17.18",
                "GHSA-35jh-r3h4-6jhm@4.17.21"), ghsaAndVersion);
    }

    private static Set<String> versionsOf(List<Advisory> advisories) {
        return advisories.stream()
                .map(Advisory::getVersion)
                .collect(Collectors.toCollection(TreeSet::new));
    }

    /**
     * Invokes the private static parsing logic without starting a yarn process.
     *
     * @param advisoryJsonLines one or more `yarn npm audit --json` output lines
     * @return the parsed advisories
     * @throws Exception if the reflective invocation fails
     */
    private static List<Advisory> parseAdvisories(String... advisoryJsonLines) throws Exception {
        final Method parseAdvisoryJsons = YarnAuditAnalyzer.class.getDeclaredMethod("parseAdvisoryJsons", List.class);
        parseAdvisoryJsons.setAccessible(true);
        final List<JSONObject> jsonObjects = Arrays.stream(advisoryJsonLines)
                .map(JSONObject::new)
                .collect(Collectors.toList());
        @SuppressWarnings("unchecked")
        final List<Advisory> advisories = (List<Advisory>) parseAdvisoryJsons.invoke(null, jsonObjects);
        return advisories;
    }
}
