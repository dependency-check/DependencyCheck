package org.owasp.dependencycheck.data.ossindex;

import org.joda.time.Duration;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.dependencycheck.utils.Settings;
import org.sonatype.ossindex.service.client.OssindexClientConfiguration;
import org.sonatype.ossindex.service.client.cache.DirectoryCache;
import org.sonatype.ossindex.service.client.marshal.GsonMarshaller;
import org.sonatype.ossindex.service.client.marshal.Marshaller;
import org.sonatype.ossindex.service.client.transport.Transport;

import java.io.IOException;
import java.net.URI;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.nullValue;
import static org.owasp.dependencycheck.data.ossindex.OssIndexHelper.setSonatypeGuideCredentials;

@SuppressWarnings("resource")
@ExtendWith(MockitoExtension.class)
class OssIndexClientProviderTest {

    private final Settings settings = new Settings();

    @Captor
    ArgumentCaptor<OssindexClientConfiguration> configCaptor;
    @Captor
    ArgumentCaptor<Transport> transportCaptor;
    @Captor
    ArgumentCaptor<Marshaller> marshallerCaptor;

    @BeforeEach
    void setUp() {
        setSonatypeGuideCredentials(settings);
    }

    @Test
    void shouldUseDefaultConfiguration() {
        try (var clientCreation = OssIndexHelper.stubClientCreation()) {
            OssIndexClientProvider.create(settings);
            clientCreation.verify(() -> OssIndexClientProvider.newClientFor(configCaptor.capture(), transportCaptor.capture(), marshallerCaptor.capture()));

            OssindexClientConfiguration config = configCaptor.getValue();
            assertThat(config.getAuthConfiguration().getPassword(), is("sonatype_pat_abcdef"));
            assertThat(config.getBaseUrl(), is(URI.create(OssIndexClientProvider.DEFAULT_BASE_URL)));
            assertThat(config.getBatchSize(), is(128));

            ODCConnectionTransport transport = assertTransportConfigured();
            assertThat(transport.getUserAgent().get(), matchesPattern("dependency-check/.+ \\(.*\\)"));

            assertThat(marshallerCaptor.getValue(), instanceOf(GsonMarshaller.class));
        }
    }

    @Test
    void canChangeConfigValues() {
        settings.setString(Settings.KEYS.ANALYZER_OSSINDEX_URL, "https://some.other.url");
        settings.setInt(Settings.KEYS.ANALYZER_OSSINDEX_BATCH_SIZE, 100);

        try (var clientCreation = OssIndexHelper.stubClientCreation()) {
            OssIndexClientProvider.create(settings);
            clientCreation.verify(() -> OssIndexClientProvider.newClientFor(configCaptor.capture(), transportCaptor.capture(), marshallerCaptor.capture()));

            ODCConnectionTransport transport = assertTransportConfigured();
            assertThat(transport.getUserAgent().get(), matchesPattern("dependency-check/.+ \\(.*\\)"));

            OssindexClientConfiguration config = configCaptor.getValue();
            assertThat(config.getBaseUrl(), is(URI.create("https://some.other.url")));
            assertThat(config.getBatchSize(), is(100));
        }
    }

    private @NonNull ODCConnectionTransport assertTransportConfigured() {
        Transport transport = transportCaptor.getValue();
        assertThat(transport, instanceOf(ODCConnectionTransport.class));
        return (ODCConnectionTransport) transport;
    }

    @Nested
    class CacheConfig {
        @Test
        void shouldUseDefaultCacheConfiguration() throws IOException {
            try (var clientCreation = OssIndexHelper.stubClientCreation()) {
                OssIndexClientProvider.create(settings);
                clientCreation.verify(() -> OssIndexClientProvider.newClientFor(configCaptor.capture(), transportCaptor.capture(), marshallerCaptor.capture()));

                DirectoryCache.Configuration config = assertDirectoryCacheConfigured();
                assertThat(config.getBaseDir(), is(settings.getDataDirectory().toPath().resolve("oss_cache")));
                assertThat(config.getExpireAfter(), is(Duration.standardHours(24)));
            }
        }

        @Test
        void canConfigureCache() {
            settings.setInt(Settings.KEYS.ANALYZER_OSSINDEX_CACHE_VALID_FOR_HOURS, 1);
            try (var clientCreation = OssIndexHelper.stubClientCreation()) {
                OssIndexClientProvider.create(settings);
                clientCreation.verify(() -> OssIndexClientProvider.newClientFor(configCaptor.capture(), transportCaptor.capture(), marshallerCaptor.capture()));

                DirectoryCache.Configuration config = assertDirectoryCacheConfigured();
                assertThat(config.getExpireAfter(), is(Duration.standardHours(1)));
            }
        }

        private DirectoryCache.Configuration assertDirectoryCacheConfigured() {
            OssindexClientConfiguration config = configCaptor.getValue();
            assertThat(config.getCacheConfiguration(), instanceOf(DirectoryCache.Configuration.class));
            return (DirectoryCache.Configuration) config.getCacheConfiguration();
        }

        @Test
        void canDisableCache() {
            settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_USE_CACHE, false);
            try (var clientCreation = OssIndexHelper.stubClientCreation()) {
                OssIndexClientProvider.create(settings);
                clientCreation.verify(() -> OssIndexClientProvider.newClientFor(configCaptor.capture(), transportCaptor.capture(), marshallerCaptor.capture()));

                OssindexClientConfiguration config = configCaptor.getValue();
                assertThat(config.getCacheConfiguration(), nullValue());
            }
        }
    }
}