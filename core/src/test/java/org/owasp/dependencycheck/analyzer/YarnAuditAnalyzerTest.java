package org.owasp.dependencycheck.analyzer;

import org.apache.commons.io.IOUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.data.nodeaudit.NpmAuditParser;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class YarnAuditAnalyzerTest extends BaseTest {

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
    void testNpmAuditParserCompatibility() throws IOException, JSONException {
        NpmAuditParser npmAuditParser = new NpmAuditParser();
        JSONObject auditJson = new JSONObject(
                IOUtils.toString(getResourceAsStream(this, "yarn/yarn-classic-npm-audit.json"), StandardCharsets.UTF_8));
        List<Advisory> advisories = npmAuditParser.parse(auditJson);
        assertThat(advisories.size(), is(1));
        assertThat(advisories.get(0).getModuleName(), is("uglify-js"));
        assertThat(advisories.get(0).getVersion(), is("2.4.24"));
    }

    /**
     * Tests for {@code analyzePackageWithYarnClassic} and {@code fetchNpmAuditJson},
     * exercised indirectly through {@link YarnAuditAnalyzer#analyzeDependency}.
     *
     * <p>Fake yarn and npm scripts are injected via {@link Settings#KEYS#ANALYZER_YARN_PATH} and
     * {@link Settings#KEYS#ANALYZER_NPM_PATH} so that {@code prepare(engine)} succeeds without a
     * real Node.js installation, while the analyzer still goes through its full code path.
     */
    @Nested
    class YarnClassicTests {

        @TempDir
        Path tempDir;

        Engine engine;

        @BeforeEach
        void setUpEngine() {
            engine = new Engine(getSettings());
        }

        @AfterEach
        void tearDownEngine() {
            if (engine != null) {
                engine.close();
            }
        }

        // ── script helpers ─────────────────────────────────────────────────────

        /** Creates a fake {@code yarn} script that prints the given version string. */
        private File createFakeYarnOutputtingVersion(String version) throws IOException {
            boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
            Path scriptFile;
            if (isWindows) {
                scriptFile = Files.createTempFile(tempDir, "fake-yarn", ".bat");
                Files.writeString(scriptFile, "@echo off\r\necho " + version + "\r\n", StandardCharsets.UTF_8);
            } else {
                scriptFile = Files.createTempFile(tempDir, "fake-yarn", ".sh");
                Files.writeString(scriptFile, "#!/bin/sh\necho '" + version + "'\n", StandardCharsets.UTF_8);
                scriptFile.toFile().setExecutable(true);
            }
            return scriptFile.toFile();
        }

        /** Creates a fake {@code npm} script whose stdout contains the given JSON content. */
        private File createFakeNpmWithOutput(String jsonContent) throws IOException {
            Path jsonFile = Files.createTempFile(tempDir, "npm-output", ".json");
            Files.writeString(jsonFile, jsonContent, StandardCharsets.UTF_8);

            boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
            Path scriptFile;
            if (isWindows) {
                scriptFile = Files.createTempFile(tempDir, "fake-npm", ".bat");
                Files.writeString(scriptFile,
                        "@echo off\r\ntype \"" + jsonFile.toAbsolutePath() + "\"\r\n",
                        StandardCharsets.UTF_8);
            } else {
                scriptFile = Files.createTempFile(tempDir, "fake-npm", ".sh");
                Files.writeString(scriptFile,
                        "#!/bin/sh\ncat \"" + jsonFile.toAbsolutePath() + "\"\n",
                        StandardCharsets.UTF_8);
                scriptFile.toFile().setExecutable(true);
            }
            return scriptFile.toFile();
        }

        // ── analyzer setup helper ──────────────────────────────────────────────

        /**
         * Configures settings so that {@code cacheYarnCommandPath()} and {@code cacheNpmCommandPath()}
         * pick up the supplied fake scripts, then initialises and prepares the analyzer.
         */
        private YarnAuditAnalyzer createPreparedAnalyzer(File fakeYarn, File fakeNpm)
                throws InitializationException {
            getSettings().setString(Settings.KEYS.ANALYZER_YARN_PATH, fakeYarn.getAbsolutePath());
            getSettings().setString(Settings.KEYS.ANALYZER_NPM_PATH, fakeNpm.getAbsolutePath());
            YarnAuditAnalyzer analyzer = new YarnAuditAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            return analyzer;
        }

        /** Creates a non-empty {@code yarn.lock} in the given directory. */
        private File createLockFile(Path dir) throws IOException {
            Path lockFile = dir.resolve("yarn.lock");
            Files.writeString(lockFile, "# yarn lockfile v1\n", StandardCharsets.UTF_8);
            return lockFile.toFile();
        }

        // ── tests ──────────────────────────────────────────────────────────────

        @Test
        void testAnalyzeDependencyWithYarnClassicParsesV1Format() throws Exception {
            String v1Json = IOUtils.toString(
                    getResourceAsStream(YarnAuditAnalyzerTest.this, "yarn/yarn-classic-npm-audit.json"),
                    StandardCharsets.UTF_8);
            YarnAuditAnalyzer analyzer = createPreparedAnalyzer(
                    createFakeYarnOutputtingVersion("1.22.0"),
                    createFakeNpmWithOutput(v1Json));

            Path projectDir = Files.createTempDirectory(tempDir, "project");
            Dependency dependency = new Dependency(createLockFile(projectDir));

            analyzer.analyzeDependency(dependency, engine);

            Dependency[] results = engine.getDependencies();
            assertThat(results.length, greaterThanOrEqualTo(1));
            assertTrue(results[0].getEvidence(EvidenceType.PRODUCT).toString().contains("uglify-js"));
            assertTrue(results[0].getEvidence(EvidenceType.VERSION).toString().contains("2.4.24"));
        }

        @Test
        void testAnalyzeDependencyWithYarnClassicParsesV2Format() throws Exception {
            String v2Json = IOUtils.toString(
                    getResourceAsStream(YarnAuditAnalyzerTest.this, "nodeaudit/npm-audit-v2.json"),
                    StandardCharsets.UTF_8);
            YarnAuditAnalyzer analyzer = createPreparedAnalyzer(
                    createFakeYarnOutputtingVersion("1.22.0"),
                    createFakeNpmWithOutput(v2Json));

            // NpmAuditV2Parser reads package-lock.json from the same directory for version lookup
            Path projectDir = Files.createTempDirectory(tempDir, "project");
            Files.writeString(projectDir.resolve("package-lock.json"),
                    "{\"packages\": {\"node_modules/uglify-js\": {\"version\": \"2.4.24\"}}}",
                    StandardCharsets.UTF_8);
            Dependency dependency = new Dependency(createLockFile(projectDir));

            analyzer.analyzeDependency(dependency, engine);

            Dependency[] results = engine.getDependencies();
            assertThat(results.length, greaterThanOrEqualTo(1));
            assertTrue(results[0].getEvidence(EvidenceType.PRODUCT).toString().contains("uglify-js"));
            assertTrue(results[0].getEvidence(EvidenceType.VERSION).toString().contains("2.4.24"));
        }

        @Test
        void testAnalyzeDependencyWithYarnClassicSkipDevDependencies() throws Exception {
            // ANALYZER_NODE_AUDIT_SKIPDEV=true causes analyzePackageWithYarnClassic to pass
            // skipDevDependencies=true into fetchNpmAuditJson, exercising the --omit=dev branch
            getSettings().setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_SKIPDEV, true);
            String v1Json = IOUtils.toString(
                    getResourceAsStream(YarnAuditAnalyzerTest.this, "yarn/yarn-classic-npm-audit.json"),
                    StandardCharsets.UTF_8);
            YarnAuditAnalyzer analyzer = createPreparedAnalyzer(
                    createFakeYarnOutputtingVersion("1.22.0"),
                    createFakeNpmWithOutput(v1Json));

            Path projectDir = Files.createTempDirectory(tempDir, "project");
            Dependency dependency = new Dependency(createLockFile(projectDir));

            analyzer.analyzeDependency(dependency, engine);

            assertThat(engine.getDependencies().length, greaterThanOrEqualTo(1));
        }

        @Test
        void testAnalyzeDependencyWithYarnClassicInvalidJsonThrowsAnalysisException() throws Exception {
            YarnAuditAnalyzer analyzer = createPreparedAnalyzer(
                    createFakeYarnOutputtingVersion("1.22.0"),
                    createFakeNpmWithOutput("not valid json"));

            Path projectDir = Files.createTempDirectory(tempDir, "project");
            Dependency dependency = new Dependency(createLockFile(projectDir));

            AnalysisException ex = assertThrows(AnalysisException.class,
                    () -> analyzer.analyzeDependency(dependency, engine));

            assertThat(ex.getMessage(), containsString("npm audit returned an invalid response"));
        }
    }
}
