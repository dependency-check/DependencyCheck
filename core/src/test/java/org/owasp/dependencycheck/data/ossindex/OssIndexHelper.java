package org.owasp.dependencycheck.data.ossindex;

import org.mockito.MockedStatic;
import org.owasp.dependencycheck.utils.Settings;
import org.sonatype.ossindex.service.client.OssindexClient;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;

public class OssIndexHelper {
    private OssIndexHelper() {}

    public static void setSonatypeGuideCredentials(final Settings settings) {
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, true);
        settings.setString(Settings.KEYS.ANALYZER_OSSINDEX_PASSWORD, "sonatype_pat_abcdef");
    }

    public static void setLegacyOssIndexCredentials(final Settings settings) {
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, true);
        settings.setString(Settings.KEYS.ANALYZER_OSSINDEX_USER, "user");
        settings.setString(Settings.KEYS.ANALYZER_OSSINDEX_PASSWORD, "api-token");
    }

    @SuppressWarnings("resource")
    static MockedStatic<OssIndexClientProvider> stubClientCreation() {
        MockedStatic<OssIndexClientProvider> mockedClient = mockStatic(OssIndexClientProvider.class);
        mockedClient.when(() -> OssIndexClientProvider.create(any())).thenCallRealMethod();
        mockedClient.when(() -> OssIndexClientProvider.newClientFor(any(), any(), any())).thenReturn(null);
        return mockedClient;
    }

    @SuppressWarnings("resource")
    public static MockedStatic<OssIndexClientProvider> withClientCreation(OssindexClient client) {
        MockedStatic<OssIndexClientProvider> mockedClient = mockStatic(OssIndexClientProvider.class);
        mockedClient.when(() -> OssIndexClientProvider.create(any())).thenReturn(client);
        return mockedClient;
    }
}
