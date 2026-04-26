package org.owasp.dependencycheck.analyzer;

import org.apache.hc.core5.http.HttpStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.Settings.KEYS;

import org.sonatype.goodies.packageurl.PackageUrl;
import org.sonatype.ossindex.service.api.componentreport.ComponentReport;
import org.sonatype.ossindex.service.client.OssindexClient;
import org.sonatype.ossindex.service.client.transport.Transport;

import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.owasp.dependencycheck.data.ossindex.OssIndexHelper.setLegacyOssIndexCredentials;
import static org.owasp.dependencycheck.data.ossindex.OssIndexHelper.setSonatypeGuideCredentials;
import static org.owasp.dependencycheck.data.ossindex.OssIndexHelper.withClientCreation;

class OssIndexAnalyzerTest extends BaseTest {

    @Nested
    class Analyze {
        private OssIndexAnalyzer analyzer;

        @BeforeEach
        public void setUp() {
            analyzer = new OssIndexAnalyzer();
        }

        @AfterEach
        public void tearDown() throws Exception {
            analyzer.close();
        }

        @Test
        void should_enrich_be_included_in_mutex_to_prevent_NPE() throws Exception {

            ClosedDuringEnrichOssIndexAnalyzer analyzer = new ClosedDuringEnrichOssIndexAnalyzer();

            Settings settings = getSettings();
            setSonatypeGuideCredentials(settings);

            Engine engine = new Engine(settings);
            analyzer.initialize(settings);
            analyzer.prepareAnalyzer(engine);
            Dependency dependency = addTestDependencyTo(engine);

            Identifier toEnrich = dependency.getSoftwareIdentifiers().stream().findFirst().orElseThrow();
            // When
            try (engine; var ignored = withClientCreation(new SingleOkReportOssIndexClient())) {
                analyzer.analyzeDependency(dependency, engine);
            }
            assertThat(toEnrich.getUrl(), startsWith("https://guide.sonatype.com/component/maven/test%3Atest/1.0"));

            analyzer.awaitPendingClosure();
        }

        @ParameterizedTest
        @MethodSource("org.owasp.dependencycheck.analyzer.OssIndexAnalyzerTest#handledErrorsPlusAnother")
        void should_return_a_dedicated_error_messages_for_responses_where_possible(Map.Entry<Integer, String> statusCodeToDedicatedMessage) throws Exception {
            // Given
            Settings settings = getSettings();
            setSonatypeGuideCredentials(settings);
            settings.setBoolean(KEYS.ANALYZER_OSSINDEX_USE_CACHE, false);

            Engine engine = new Engine(settings);
            analyzer.initialize(settings);
            analyzer.prepareAnalyzer(engine);
            Dependency dependency = addTestDependencyTo(engine);

            // When
            try (engine; var ignored = withClientCreation(throwingOssIndex(new Transport.TransportException("Unexpected response; status: " + statusCodeToDedicatedMessage.getKey())))) {
                Throwable e = assertThrows(AnalysisException.class, () -> analyzer.analyzeDependency(dependency, engine));
                assertThat(e.getMessage(), containsString("Sonatype OSS Index / Guide " + statusCodeToDedicatedMessage.getValue()));
                assertFalse(analyzer.isEnabled());

                analyzer.setEnabled(true);
                settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, true);
                analyzer.initialize(settings);
                assertDoesNotThrow(() -> analyzer.analyzeDependency(dependency, engine),
                        "Analysis exception thrown upon remote error although only a warning should have been logged");
                assertFalse(analyzer.isEnabled());
            }
        }

        @Test
        void should_return_a_dedicated_error_for_socket_timeouts() throws Exception {
            // Given
            Settings settings = getSettings();
            setSonatypeGuideCredentials(settings);
            settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, false);
            Engine engine = new Engine(settings);

            analyzer.initialize(settings);
            analyzer.prepareAnalyzer(engine);

            Dependency dependency = addTestDependencyTo(engine);

            // When
            try (engine; var ignored = withClientCreation(throwingOssIndex(new SocketTimeoutException("Read timed out")))) {
                Throwable e = assertThrows(AnalysisException.class, () -> analyzer.analyzeDependency(dependency, engine));
                assertThat(e.getMessage(), is("Failed to establish socket to Sonatype OSS Index / Guide"));
                assertFalse(analyzer.isEnabled());

                analyzer.setEnabled(true);
                settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, true);
                analyzer.initialize(settings);
                assertDoesNotThrow(() -> analyzer.analyzeDependency(dependency, engine),
                        "Analysis exception thrown upon remote error although only a warning should have been logged");
                assertFalse(analyzer.isEnabled());
            }
        }
    }

    private static Dependency addTestDependencyTo(Engine engine) throws Exception {
        Dependency dependency = new Dependency();
        dependency.addSoftwareIdentifier(new PurlIdentifier("maven", "test", "test", "1.0", Confidence.HIGHEST));
        engine.setDependencies(Collections.singletonList(dependency));
        return dependency;
    }

    @Nested
    class Prepare {
        @Test
        void should_disable_when_credentials_not_set() throws Exception {
            // Given
            OssIndexAnalyzer analyzer = new OssIndexAnalyzer();
            Settings settings = getSettings();
            Engine engine = new Engine(settings);
            analyzer.initialize(settings);

            // When
            analyzer.prepareAnalyzer(engine);

            // Then
            boolean enabled = analyzer.isEnabled();
            analyzer.close();
            engine.close();
            assertFalse(enabled);
        }

        @Test
        void should_disable_when_legacy_credential_missing_username() throws Exception {
            // Given
            OssIndexAnalyzer analyzer = new OssIndexAnalyzer();
            Settings settings = getSettings();
            settings.setString(KEYS.ANALYZER_OSSINDEX_PASSWORD, "api-token");
            Engine engine = new Engine(settings);
            analyzer.initialize(settings);

            // When
            analyzer.prepareAnalyzer(engine);

            // Then
            boolean enabled = analyzer.isEnabled();
            analyzer.close();
            engine.close();
            assertFalse(enabled);
        }

        @Test
        void should_enable_when_sonatype_guide_credential_set() throws Exception {
            // Given
            OssIndexAnalyzer analyzer = new OssIndexAnalyzer();
            Settings settings = getSettings();
            setSonatypeGuideCredentials(settings);
            Engine engine = new Engine(settings);
            analyzer.initialize(settings);

            // When
            analyzer.prepareAnalyzer(engine);

            // Then
            boolean enabled = analyzer.isEnabled();
            analyzer.close();
            engine.close();
            assertTrue(enabled);
        }

        @Test
        void should_enable_when_legacy_oss_index_credential_set() throws Exception {
            // Given
            OssIndexAnalyzer analyzer = new OssIndexAnalyzer();
            Settings settings = getSettings();
            setLegacyOssIndexCredentials(settings);
            Engine engine = new Engine(settings);
            analyzer.initialize(settings);

            // When
            analyzer.prepareAnalyzer(engine);

            // Then
            boolean enabled = analyzer.isEnabled();
            analyzer.close();
            engine.close();
            assertTrue(enabled);
        }
    }

    /*
     * This action is inspired by the sprout method technique displayed in
     * "Michael Feathers - Working Effectively with Legacy code".
     *
     * We want to trigger a race condition between a call to
     * OssIndexAnalyzer.closeAnalyzer() and OssIndexAnalyzer.enrich().
     *
     * The last method access data from the "reports" field while
     * closeAnalyzer() erase the reference. If enrich() is not included in
     * the "FETCH_MUTEX" synchronized statement, we can trigger a
     * NullPointerException in a multithreaded environment, which can happen
     * due to the usage of java.util.concurrent.Future.
     *
     * We want to make sure enrich() will be able to set the url of an
     * identifier and enrich it.
     */
    private static final class ClosedDuringEnrichOssIndexAnalyzer extends OssIndexAnalyzer {
        private Future<?> pendingClosureTask;

        @Override
        void enrich(Dependency dependency) {
            @SuppressWarnings("resource") ExecutorService executor = Executors.newSingleThreadExecutor();
            pendingClosureTask = executor.submit(() -> {
                try {
                    this.closeAnalyzer();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            executor.shutdown();
            super.enrich(dependency);
        }

        void awaitPendingClosure() throws ExecutionException, InterruptedException {
            pendingClosureTask.get();
        }
    }

    private static final class SingleOkReportOssIndexClient implements OssindexClient {
        @Override
        public Map<PackageUrl, ComponentReport> requestComponentReports(List<PackageUrl> coordinates) throws Exception {
            HashMap<PackageUrl, ComponentReport> reports = new HashMap<>();
            ComponentReport report = requestComponentReport(coordinates.get(0));
            reports.put(report.getCoordinates(), report);
            return reports;
        }

        @Override
        public ComponentReport requestComponentReport(PackageUrl coordinates) throws Exception {
            ComponentReport report = new ComponentReport();
            report.setCoordinates(coordinates);
            report.setReference(new URI("https://guide.sonatype.com/component/maven/test%3Atest/1.0"));
            return report;
        }

        @Override
        public void close() {}
    }

    private static OssindexClient throwingOssIndex(Exception exception1) throws Exception {
        OssindexClient client = mock(OssindexClient.class);
        when(client.requestComponentReport(any())).thenThrow(exception1);
        when(client.requestComponentReports(any())).thenThrow(exception1);
        return client;
    }

    static Stream<Map.Entry<Integer, String>> handledErrorsPlusAnother() {
        return Stream.concat(
                OssIndexAnalyzer.OSSINDEX_KNOWN_USER_ERRORS.entrySet().stream(),
                Stream.of(Map.entry(HttpStatus.SC_INTERNAL_SERVER_ERROR, "request had unknown fatal error"))
        );
    }
}
