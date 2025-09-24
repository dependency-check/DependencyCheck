package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OssIndexAnalyzerTest extends BaseTest {

    @Test
    void should_enrich_be_included_in_mutex_to_prevent_NPE()
            throws Exception {

        // Given
        SproutOssIndexAnalyzer analyzer = new SproutOssIndexAnalyzer();

        Identifier identifier = new PurlIdentifier("maven", "test", "test", "1.0",
                Confidence.HIGHEST);

        Dependency dependency = new Dependency();
        dependency.addSoftwareIdentifier(identifier);
        Settings settings = getSettings();
        setCredentials(settings);
        Engine engine = new Engine(settings);
        engine.setDependencies(Collections.singletonList(dependency));

        analyzer.initialize(settings);
        analyzer.prepareAnalyzer(engine);

        String expectedOutput = "https://ossindex.sonatype.org/component/pkg:maven/test/test@1.0";

        // When
        analyzer.analyzeDependency(dependency, engine);

        // Then
        assertTrue(identifier.getUrl().startsWith(expectedOutput));
        analyzer.awaitPendingClosure();
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
     * the "FETCH_MUTIX" synchronized statement, we can trigger a
     * NullPointeException in a multithreaded environment, which can happen
     * due to the usage of java.util.concurrent.Future.
     *
     * We want to make sure enrich() will be able to set the url of an
     * identifier and enrich it.
     */
    static final class SproutOssIndexAnalyzer extends OssIndexAnalyzer {
        private Future<?> pendingClosureTask;
        @Override
        OssindexClient newOssIndexClient() {
                return new OssIndexClientOk();
        }

        @Override
        void enrich(Dependency dependency) {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            pendingClosureTask = executor.submit(() -> {
                try {
                    this.closeAnalyzer();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            super.enrich(dependency);
        }

        void awaitPendingClosure() throws ExecutionException, InterruptedException {
            pendingClosureTask.get();
        }
    }

    private static final class OssIndexClientOk implements OssindexClient {

        @Override
        public Map<PackageUrl, ComponentReport> requestComponentReports(List<PackageUrl> coordinates) throws Exception {
            HashMap<PackageUrl, ComponentReport> reports = new HashMap<>();
            ComponentReport report = new ComponentReport();
            PackageUrl packageUrl = coordinates.get(0);
            report.setCoordinates(packageUrl);
            report.setReference(new URI("https://ossindex.sonatype.org/component/pkg:maven/test/test@1.0?utm_source=dependency-check&utm_medium=integration&utm_content=12.1.4-SNAPSHOT"));
            reports.put(packageUrl, report);
            return reports;
        }

        @Override
        public ComponentReport requestComponentReport(PackageUrl coordinates) throws Exception {
            return new ComponentReport();
        }

        @Override
        public void close() {

        }
    }

    @Test
    void should_analyzeDependency_return_a_dedicated_error_message_when_403_response_from_sonatype() throws Exception {
        // Given
        OssIndexAnalyzer analyzer = new OssIndexAnalyzerThrowing403();
        Settings settings = getSettings();
        setCredentials(settings);
        Engine engine = new Engine(settings);

        analyzer.initialize(settings);
        analyzer.prepareAnalyzer(engine);

        Identifier identifier = new PurlIdentifier("maven", "test", "test", "1.0",
                Confidence.HIGHEST);

        Dependency dependency = new Dependency();
        dependency.addSoftwareIdentifier(identifier);
        engine.setDependencies(Collections.singletonList(dependency));

        // When
        AnalysisException output = new AnalysisException();
        try {
            analyzer.analyzeDependency(dependency, engine);
        } catch (AnalysisException e) {
            output = e;
        }

        // Then
        assertEquals("OSS Index access forbidden", output.getMessage());
        analyzer.close();
    }


    @Test
    void should_analyzeDependency_only_warn_when_transport_error_from_sonatype() throws Exception {
        // Given
        OssIndexAnalyzer analyzer = new OssIndexAnalyzerThrowing502();
        Settings settings = getSettings();
        setCredentials(settings);
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, true);
        Engine engine = new Engine(settings);

        analyzer.initialize(settings);
        analyzer.prepareAnalyzer(engine);

        Identifier identifier = new PurlIdentifier("maven", "test", "test", "1.0",
                Confidence.HIGHEST);

        Dependency dependency = new Dependency();
        dependency.addSoftwareIdentifier(identifier);

        // When
        try (engine) {
            engine.setDependencies(Collections.singletonList(dependency));
            assertDoesNotThrow(() -> analyzer.analyzeDependency(dependency, engine),
                    "Analysis exception thrown upon remote error although only a warning should have been logged");
        } finally {
            analyzer.close();
        }
    }

    @Test
    void should_analyzeDependency_only_warn_when_socket_error_from_sonatype() throws Exception {
        // Given
        OssIndexAnalyzer analyzer = new OssIndexAnalyzerThrowingSocketTimeout();
        Settings settings = getSettings();
        setCredentials(settings);
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, true);
        analyzer.initialize(settings);

        Engine engine = new Engine(settings);
        analyzer.prepareAnalyzer(engine);

        Identifier identifier = new PurlIdentifier("maven", "test", "test", "1.0",
                Confidence.HIGHEST);

        Dependency dependency = new Dependency();
        dependency.addSoftwareIdentifier(identifier);

        // When
        try (engine) {
            engine.setDependencies(Collections.singletonList(dependency));
            assertDoesNotThrow(() -> analyzer.analyzeDependency(dependency, engine),
                    "Analysis exception thrown upon remote error although only a warning should have been logged");
        } finally {
            analyzer.close();
        }
    }


    @Test
    void should_analyzeDependency_fail_when_socket_error_from_sonatype() throws Exception {
        // Given
        OssIndexAnalyzer analyzer = new OssIndexAnalyzerThrowingSocketTimeout();
        Settings settings = getSettings();
        setCredentials(settings);
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, false);
        Engine engine = new Engine(settings);

        analyzer.initialize(settings);
        analyzer.prepareAnalyzer(engine);

        Identifier identifier = new PurlIdentifier("maven", "test", "test", "1.0",
                Confidence.HIGHEST);

        Dependency dependency = new Dependency();
        dependency.addSoftwareIdentifier(identifier);
        engine.setDependencies(Collections.singletonList(dependency));

        // When
        AnalysisException output = new AnalysisException();
        try {
            analyzer.analyzeDependency(dependency, engine);
        } catch (AnalysisException e) {
            output = e;
        }

        // Then
        assertEquals("Failed to establish socket to OSS Index", output.getMessage());
        analyzer.close();
    }

    @Test
    void should_prepareAnalyzer_disable_when_credentials_not_set() throws Exception {
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

    private static void setCredentials(final Settings settings) {
        settings.setString(KEYS.ANALYZER_OSSINDEX_USER, "user");
        settings.setString(KEYS.ANALYZER_OSSINDEX_PASSWORD, "pass");
    }

    static final class OssIndexAnalyzerThrowing403 extends OssIndexAnalyzer {
        @Override
        OssindexClient newOssIndexClient() {
            return new OssIndexClient403();
        }
    }

    private static final class OssIndexClient403 implements OssindexClient {

        @Override
        public Map<PackageUrl, ComponentReport> requestComponentReports(List<PackageUrl> coordinates) throws Exception {
            throw new Transport.TransportException("Unexpected response; status: 403");
        }

        @Override
        public ComponentReport requestComponentReport(PackageUrl coordinates) throws Exception {
            throw new Transport.TransportException("Unexpected response; status: 403");
        }

        @Override
        public void close() {

        }
    }

    static final class OssIndexAnalyzerThrowing502 extends OssIndexAnalyzer {
        @Override
        OssindexClient newOssIndexClient() {
            return new OssIndexClient502();
        }
    }

    private static final class OssIndexClient502 implements OssindexClient {

        @Override
        public Map<PackageUrl, ComponentReport> requestComponentReports(List<PackageUrl> coordinates) throws Exception {
            throw new Transport.TransportException("Unexpected response; status: 502");
        }

        @Override
        public ComponentReport requestComponentReport(PackageUrl coordinates) throws Exception {
            throw new Transport.TransportException("Unexpected response; status: 502");
        }

        @Override
        public void close() {

        }
    }

    static final class OssIndexAnalyzerThrowingSocketTimeout extends OssIndexAnalyzer {
        @Override
        OssindexClient newOssIndexClient() {
            return new OssIndexClientSocketTimeoutException();
        }
    }

    private static final class OssIndexClientSocketTimeoutException implements OssindexClient {

        @Override
        public Map<PackageUrl, ComponentReport> requestComponentReports(List<PackageUrl> coordinates) throws Exception {
            throw new SocketTimeoutException("Read timed out");
        }

        @Override
        public ComponentReport requestComponentReport(PackageUrl coordinates) throws Exception {
            throw new SocketTimeoutException("Read timed out");
        }

        @Override
        public void close() {

        }
    }
}
