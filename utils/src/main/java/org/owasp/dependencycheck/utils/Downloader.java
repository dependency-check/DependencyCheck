/*
 * This file is part of dependency-check-utils.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2024 Hans Aikema. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.apache.hc.client5.http.HttpResponseException;
import org.apache.hc.client5.http.auth.AuthCache;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.CredentialsStore;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.auth.BasicAuthCache;
import org.apache.hc.client5.http.impl.auth.BasicScheme;
import org.apache.hc.client5.http.impl.auth.SystemDefaultCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.BasicHttpClientResponseHandler;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.Method;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.BasicHttpEntity;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpRequest;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLHandshakeException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import static java.lang.String.format;

/**
 * A Utility class to centralize download logic like HTTP(S) proxy configuration and proxy- and server credential handling.
 * @author Jeremy Long, Hans Aikema
 */
public final class Downloader {

    /**
     * The builder to use for a HTTP Client that uses the configured proxy-settings
     */
    private final HttpClientBuilder httpClientBuilder;

    /**
     * The builder to use for a HTTP Client that explicitly opts out of proxy-usage
     */
    private final HttpClientBuilder httpClientBuilderExplicitNoproxy;

    /**
     * The Authentication cache for pre-emptive authentication.
     * This gets filled with credentials from the settings in {@link #configure(Settings)}.
     */
    private final AuthCache authCache = new BasicAuthCache();

    /**
     * The credentialsProvider for pre-emptive authentication.
     * This gets filled with credentials from the settings in {@link #configure(Settings)}.
     */
    private final SystemDefaultCredentialsProvider credentialsProvider = new SystemDefaultCredentialsProvider();

    /**
     * The settings
     */
    private Settings settings;

    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Downloader.class);

    /**
     * The singleton instance of the downloader
     */
    private static final Downloader INSTANCE = new Downloader();
    /**
     * The Credentials for the proxy when proxy authentication is configured in the Settings.
     */
    private Credentials proxyCreds = null;
    /**
     * A BasicScheme initialized with the proxy-credentials when proxy authentication is configured in the Settings.
     */
    private BasicScheme proxyPreEmptAuth = null;
    /**
     * The AuthScope for the proxy when proxy authentication is configured in the Settings.
     */
    private AuthScope proxyAuthScope = null;
    /**
     * The HttpHost for the proxy when proxy authentication is configured in the Settings.
     */
    private HttpHost proxyHttpHost = null;

    private Downloader() {
        // Singleton class
        final PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
        //TODO: ensure proper closure and eviction policy
        httpClientBuilder = HttpClientBuilder.create()
                .useSystemProperties()
                .setConnectionManager(connectionManager)
                .setConnectionManagerShared(true);
        httpClientBuilderExplicitNoproxy = HttpClientBuilder.create()
                .useSystemProperties()
                .setConnectionManager(connectionManager)
                .setConnectionManagerShared(true)
                .setProxySelector(new ProxySelector() {
                    @Override
                    public List<Proxy> select(URI uri) {
                        return Collections.singletonList(Proxy.NO_PROXY);
                    }

                    @Override
                    public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {

                    }
                });
    }

    /**
     * The singleton instance for downloading file resources.
     *
     * @return The singleton instance managing download credentials and proxy configuration
     */
    public static Downloader getInstance() {
        return INSTANCE;
    }

    /**
     * Initialize the Downloader from the settings.
     * Extracts the configured proxy- and credential information from the settings and system properties and
     * caches those for future use by the Downloader.
     *
     * @param settings The settings to configure from
     * @throws InvalidSettingException When improper configurations are found.
     */
    public void configure(Settings settings) throws InvalidSettingException {
        this.settings = settings;

        if (settings.getString(Settings.KEYS.PROXY_SERVER) != null) {
            // Legacy proxy configuration present
            // So don't rely on the system properties for proxy; use the legacy settings configuration
            final String proxyHost = settings.getString(Settings.KEYS.PROXY_SERVER);
            final int proxyPort = settings.getInt(Settings.KEYS.PROXY_PORT, -1);
            final String nonProxyHosts = settings.getString(Settings.KEYS.PROXY_NON_PROXY_HOSTS);
            if (nonProxyHosts != null && !nonProxyHosts.isEmpty()) {
                final ProxySelector selector = new SelectiveProxySelector(
                        new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort)),
                        nonProxyHosts.split("\\|")
                );
                httpClientBuilder.setProxySelector(selector);
            } else {
                httpClientBuilder.setProxy(new HttpHost(proxyHost, proxyPort));
            }
            if (settings.getString(Settings.KEYS.PROXY_USERNAME) != null) {
                final String proxyuser = settings.getString(Settings.KEYS.PROXY_USERNAME);
                final char[] proxypass = settings.getString(Settings.KEYS.PROXY_PASSWORD).toCharArray();
                this.proxyHttpHost = new HttpHost(null, proxyHost, proxyPort);
                this.proxyCreds = new UsernamePasswordCredentials(proxyuser, proxypass);
                this.proxyAuthScope = new AuthScope(proxyHttpHost);
                this.proxyPreEmptAuth = new BasicScheme();
                this.proxyPreEmptAuth.initPreemptive(proxyCreds);
                tryConfigureProxyCredentials(credentialsProvider, authCache);
            }
        }
        tryAddRetireJSCredentials();
        tryAddHostedSuppressionCredentials();
        tryAddKEVCredentials();
        tryAddNexusAnalyzerCredentials();
        tryAddCentralAnalyzerCredentials();
        tryAddCentralContentCredentials();
        tryAddNVDApiDatafeed();
        httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
        httpClientBuilderExplicitNoproxy.setDefaultCredentialsProvider(credentialsProvider);
    }

    private void tryAddRetireJSCredentials() throws InvalidSettingException {
        if (settings.getString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_PASSWORD) != null) {
            addUserPasswordCreds(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, "RetireJS repo.js",
                    Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_USER,
                    Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_PASSWORD
            );
        }
    }

    private void tryAddHostedSuppressionCredentials() throws InvalidSettingException {
        if (settings.getString(Settings.KEYS.HOSTED_SUPPRESSIONS_PASSWORD) != null) {
            addUserPasswordCreds(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, "Hosted suppressions",
                    Settings.KEYS.HOSTED_SUPPRESSIONS_USER,
                    Settings.KEYS.HOSTED_SUPPRESSIONS_PASSWORD
            );
        }
    }

    private void tryAddKEVCredentials() throws InvalidSettingException {
        if (settings.getString(Settings.KEYS.KEV_PASSWORD) != null) {
            addUserPasswordCreds(Settings.KEYS.KEV_URL, "Known Exploited Vulnerabilities",
                    Settings.KEYS.KEV_USER,
                    Settings.KEYS.KEV_PASSWORD
            );
        }
    }

    private void tryAddNexusAnalyzerCredentials() throws InvalidSettingException {
        if (settings.getString(Settings.KEYS.ANALYZER_NEXUS_PASSWORD) != null) {
            addUserPasswordCreds(Settings.KEYS.ANALYZER_NEXUS_URL, "Nexus Analyzer",
                    Settings.KEYS.ANALYZER_NEXUS_USER,
                    Settings.KEYS.ANALYZER_NEXUS_PASSWORD
            );
        }
    }

    private void tryAddCentralAnalyzerCredentials() throws InvalidSettingException {
        if (settings.getString(Settings.KEYS.ANALYZER_CENTRAL_PASSWORD) != null) {
            addUserPasswordCreds(Settings.KEYS.ANALYZER_CENTRAL_URL, "Central Analyzer",
                    Settings.KEYS.ANALYZER_CENTRAL_USER,
                    Settings.KEYS.ANALYZER_CENTRAL_PASSWORD
            );
        }
    }

    private void tryAddCentralContentCredentials() throws InvalidSettingException {
        if (settings.getString(Settings.KEYS.CENTRAL_CONTENT_PASSWORD) != null) {
            addUserPasswordCreds(Settings.KEYS.CENTRAL_CONTENT_URL, "Central Content",
                    Settings.KEYS.CENTRAL_CONTENT_USER,
                    Settings.KEYS.CENTRAL_CONTENT_PASSWORD
            );
        }
    }

    private void tryAddNVDApiDatafeed() throws InvalidSettingException {
        if (settings.getString(Settings.KEYS.NVD_API_DATAFEED_PASSWORD) != null) {
            addUserPasswordCreds(Settings.KEYS.NVD_API_DATAFEED_URL, "NVD API Datafeed",
                    Settings.KEYS.NVD_API_DATAFEED_USER,
                    Settings.KEYS.NVD_API_DATAFEED_PASSWORD
            );
        }
    }

    /**
     * Add user/password credentials for the host/port of the URL, all configured in the settings, to the credential-store.
     *
     * @param urlKey      The key for a configured url for which the credentials hold
     * @param desc        A descriptive text for use in error messages for this credential
     * @param userKey     The key for a configured username credential part
     * @param passwordKey The key for a configured password credential part
     * @throws InvalidSettingException When the password is empty or one of the other keys are not found in the settings.
     */
    private void addUserPasswordCreds(String urlKey, String desc, String userKey, String passwordKey)
            throws InvalidSettingException {
        final String theUser = settings.getString(userKey);
        final String theURL = settings.getString(urlKey);
        final char[] thePass = settings.getString(passwordKey, "").toCharArray();
        if (theUser == null || theURL == null || thePass.length == 0) {
            throw new InvalidSettingException(desc + " URL and username are required when setting " + desc + " password");
        }
        try {
            final URL parsedURL = new URL(theURL);
            final HttpHost scopeHost = new HttpHost(parsedURL.getProtocol(), parsedURL.getHost(), parsedURL.getPort());
            addCredentials(credentialsProvider, scopeHost, desc, theUser, thePass, authCache);
        } catch (MalformedURLException e) {
            throw new InvalidSettingException(desc + " URL must be a valid URL", e);
        }
    }

    private static void addCredentials(CredentialsStore credentialsStore, HttpHost scopeHost, String messageScope, String theUser, char[] thePass,
                                                              AuthCache authCache)
            throws InvalidSettingException {
        final String schemeName = scopeHost.getSchemeName();
        if ("file".equals(schemeName)) {
            LOGGER.warn("Credentials are not supported for file-protocol, double-check your configuration options for {}.", messageScope);
            return;
        } else if ("http".equals(schemeName)) {
            LOGGER.warn("Insecure configuration: Basic Credentials are configured to be used over a plain http connection for {}. "
                    + "Consider migrating to https to guard the credentials.", messageScope);
        } else if (!"https".equals(schemeName)) {
            throw new InvalidSettingException("Unsupported protocol in the " + messageScope
                    + " URL; only file, http and https are supported");
        }
        final UsernamePasswordCredentials creds = new UsernamePasswordCredentials(theUser, thePass);
        final AuthScope scope = new AuthScope(scopeHost, null, null);
        credentialsStore.setCredentials(scope, creds);
        final BasicScheme basicAuth = new BasicScheme();
        basicAuth.initPreemptive(creds);
        authCache.put(scopeHost, basicAuth);
    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     *
     * @param url        the URL of the file to download
     * @param outputPath the path to the save the file to
     * @throws DownloadFailedException       is thrown if there is an error downloading the file
     * @throws URLConnectionFailureException is thrown when certificate-chain trust errors occur downloading the file
     * @throws TooManyRequestsException      thrown when a 429 is received
     * @throws ResourceNotFoundException     thrown when a 404 is received
     */
    public void fetchFile(URL url, File outputPath)
            throws DownloadFailedException, TooManyRequestsException, ResourceNotFoundException, URLConnectionFailureException {
        fetchFile(url, outputPath, true);
    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     *
     * @param url        the URL of the file to download
     * @param outputPath the path to the save the file to
     * @param useProxy   whether to use the configured proxy when downloading
     *                   files
     * @throws DownloadFailedException       is thrown if there is an error downloading the file
     * @throws URLConnectionFailureException is thrown when certificate-chain trust errors occur downloading the file
     * @throws TooManyRequestsException      thrown when a 429 is received
     * @throws ResourceNotFoundException     thrown when a 404 is received
     */
    public void fetchFile(URL url, File outputPath, boolean useProxy) throws DownloadFailedException,
            TooManyRequestsException, ResourceNotFoundException, URLConnectionFailureException {
        try {
            if ("file".equals(url.getProtocol())) {
                final Path p = Paths.get(url.toURI());
                Files.copy(p, outputPath.toPath(), StandardCopyOption.REPLACE_EXISTING);
            } else {
                final BasicClassicHttpRequest req;
                req = new BasicClassicHttpRequest(Method.GET, url.toURI());
                try (CloseableHttpClient hc = useProxy ? httpClientBuilder.build() : httpClientBuilderExplicitNoproxy.build()) {
                    final SaveToFileResponseHandler responseHandler = new SaveToFileResponseHandler(outputPath);
                    hc.execute(req, getPreEmptiveAuthContext(), responseHandler);
                }
            }
        } catch (HttpResponseException hre) {
            wrapAndThrowHttpResponseException(url.toString(), hre);
        } catch (SSLHandshakeException ex) {
            if (ex.getMessage().contains("unable to find valid certification path to requested target")) {
                final String msg = String.format("Unable to connect to '%s' - the Java trust store does not contain a trusted root for the cert. "
                        + "Please see https://github.com/jeremylong/InstallCert for one method of updating the trusted certificates.", url);
                throw new URLConnectionFailureException(msg, ex);
            }
            final String msg = format("Download failed, unable to copy '%s' to '%s'; %s", url, outputPath.getAbsolutePath(), ex.getMessage());
            throw new DownloadFailedException(msg, ex);
        } catch (RuntimeException | URISyntaxException | IOException ex) {
            final String msg = format("Download failed, unable to copy '%s' to '%s'; %s", url, outputPath.getAbsolutePath(), ex.getMessage());
            throw new DownloadFailedException(msg, ex);
        }
    }

    private static void wrapAndThrowHttpResponseException(String url, HttpResponseException hre)
            throws ResourceNotFoundException, TooManyRequestsException, DownloadFailedException {
        final String messageFormat = "%s - Server status: %d - Server reason: %s";
        switch (hre.getStatusCode()) {
            case 404:
                throw new ResourceNotFoundException(String.format(messageFormat, url, hre.getStatusCode(), hre.getReasonPhrase()), hre);
            case 429:
                throw new TooManyRequestsException(String.format(messageFormat, url, hre.getStatusCode(), hre.getReasonPhrase()), hre);
            default:
                throw new DownloadFailedException(String.format(messageFormat, url, hre.getStatusCode(), hre.getReasonPhrase()), hre);
        }
    }

    /**
     * Retrieves a file from a given URL using an ad-hoc created CredentialsProvider if needed
     * and saves it to the outputPath.
     *
     * @param url         the URL of the file to download
     * @param outputPath  the path to the save the file to
     * @param useProxy    whether to use the configured proxy when downloading
     *                    files
     * @param userKey     the settings key for the username to be used
     * @param passwordKey the settings key for the password to be used
     * @throws DownloadFailedException       is thrown if there is an error downloading the file
     * @throws URLConnectionFailureException is thrown when certificate-chain trust errors occur downloading the file
     * @throws TooManyRequestsException      thrown when a 429 is received
     * @throws ResourceNotFoundException     thrown when a 404 is received
     * @implNote This method should only be used in cases where the target host cannot be determined beforehand from settings, so that ad-hoc
     * Credentials needs to be constructed for the target URL when the user/password keys point to configured credentials. The method delegates to
     * {@link #fetchFile(URL, File, boolean)} when credentials are not configured for the given keys or the resource points to a file.
     */
    public void fetchFile(URL url, File outputPath, boolean useProxy, String userKey, String passwordKey) throws DownloadFailedException,
            TooManyRequestsException, ResourceNotFoundException, URLConnectionFailureException {
        if ("file".equals(url.getProtocol())
                || userKey == null || settings.getString(userKey) == null
                || passwordKey == null || settings.getString(passwordKey) == null
        ) {
            // no credentials configured, so use the default fetchFile
            fetchFile(url, outputPath, useProxy);
            return;
        }
        final String theProtocol = url.getProtocol();
        if (!("http".equals(theProtocol) || "https".equals(theProtocol))) {
            throw new DownloadFailedException("Unsupported protocol in the URL; only file, http and https are supported");
        }
        try {
            final HttpClientContext dedicatedAuthContext = HttpClientContext.create();
            final CredentialsStore dedicatedCredentialStore = new SystemDefaultCredentialsProvider();
            final HttpHost scopeHost = new HttpHost(url.getProtocol(), url.getHost(), url.getPort());
            final AuthCache dedicatedAuthCache = new BasicAuthCache();
            addCredentials(dedicatedCredentialStore, scopeHost, url.toString(), settings.getString(userKey),
                    settings.getString(passwordKey).toCharArray(), dedicatedAuthCache);
            if (useProxy && proxyAuthScope != null) {
                tryConfigureProxyCredentials(dedicatedCredentialStore, dedicatedAuthCache);
            }
            dedicatedAuthContext.setCredentialsProvider(dedicatedCredentialStore);
            dedicatedAuthContext.setAuthCache(dedicatedAuthCache);
            try (CloseableHttpClient hc = useProxy ? httpClientBuilder.build() : httpClientBuilderExplicitNoproxy.build()) {
                final BasicClassicHttpRequest req = new BasicClassicHttpRequest(Method.GET, url.toURI());
                final SaveToFileResponseHandler responseHandler = new SaveToFileResponseHandler(outputPath);
                hc.execute(req, dedicatedAuthContext, responseHandler);
            }
        } catch (HttpResponseException hre) {
            wrapAndThrowHttpResponseException(url.toString(), hre);
        } catch (SSLHandshakeException ex) {
            if (ex.getMessage().contains("unable to find valid certification path to requested target")) {
                final String msg = String.format("Unable to connect to '%s' - the Java trust store does not contain a trusted root for the cert. "
                        + "Please see https://github.com/jeremylong/InstallCert for one method of updating the trusted certificates.", url);
                throw new URLConnectionFailureException(msg, ex);
            }
            final String msg = format("Download failed, unable to copy '%s' to '%s'; %s", url, outputPath.getAbsolutePath(), ex.getMessage());
            throw new DownloadFailedException(msg, ex);
        } catch (RuntimeException | URISyntaxException | IOException ex) {
            final String msg = format("Download failed, unable to copy '%s' to '%s'; %s", url, outputPath.getAbsolutePath(), ex.getMessage());
            throw new DownloadFailedException(msg, ex);
        }
    }

    /**
     * Add the proxy credentials to the CredentialsProvider and AuthCache instances when proxy-authentication is configured in the settings.
     * @param credentialsProvider The credentialStore to configure the credentials in
     * @param authCache The AuthCache to cache the pre-empted credentials in
     */
    private void tryConfigureProxyCredentials(@NotNull CredentialsStore credentialsProvider, @NotNull AuthCache authCache) {
        if (proxyPreEmptAuth != null) {
            credentialsProvider.setCredentials(proxyAuthScope, proxyCreds);
            authCache.put(proxyHttpHost, proxyPreEmptAuth);
        }
    }

    /**
     * Posts a payload to the URL and returns the response as a string.
     *
     * @param url         the URL to POST to
     * @param payload     the Payload to post
     * @param payloadType the string describing the payload's mime-type
     * @param hdr         Additional headers to add to the HTTP request
     * @return the content of the response
     * @throws DownloadFailedException       is thrown if there is an error downloading the file
     * @throws URLConnectionFailureException is thrown when certificate-chain trust errors occur downloading the file
     * @throws TooManyRequestsException      thrown when a 429 is received
     * @throws ResourceNotFoundException     thrown when a 404 is received
     */
    public String postBasedFetchContent(URI url, String payload, ContentType payloadType, List<Header> hdr)
            throws DownloadFailedException, TooManyRequestsException, ResourceNotFoundException, URLConnectionFailureException {
        try {
            if (url.getScheme() == null || !url.getScheme().toLowerCase(Locale.ROOT).matches("^https?")) {
                throw new IllegalArgumentException("Unsupported protocol in the URL; only http and https are supported");
            } else {
                final BasicClassicHttpRequest req;
                req = new BasicClassicHttpRequest(Method.POST, url);
                req.setEntity(new StringEntity(payload, payloadType));
                for (Header h : hdr) {
                    req.addHeader(h);
                }
                final String result;
                try (CloseableHttpClient hc = httpClientBuilder.build()) {
                    result = hc.execute(req, getPreEmptiveAuthContext(), new BasicHttpClientResponseHandler());
                }
                return result;
            }
        } catch (HttpResponseException hre) {
            wrapAndThrowHttpResponseException(url.toString(), hre);
            throw new InternalError("wrapAndThrowHttpResponseException will always throw an exception but Java compiler fails to spot it");
        } catch (SSLHandshakeException ex) {
            if (ex.getMessage().contains("unable to find valid certification path to requested target")) {
                final String msg = String.format("Unable to connect to '%s' - the Java trust store does not contain a trusted root for the cert. "
                        + "Please see https://github.com/jeremylong/InstallCert for one method of updating the trusted certificates.", url);
                throw new URLConnectionFailureException(msg, ex);
            }
            final String msg = format("Download failed, error downloading '%s'; %s", url, ex.getMessage());
            throw new DownloadFailedException(msg, ex);
        } catch (IOException | RuntimeException ex) {
            final String msg = format("Download failed, error downloading '%s'; %s", url, ex.getMessage());
            throw new DownloadFailedException(msg, ex);
        }
    }

    /**
     * Retrieves a file from a given URL and returns the contents.
     *
     * @param url     the URL of the file to download
     * @param charset The characterset to use to interpret the binary content of the file
     * @return the content of the file
     * @throws DownloadFailedException   is thrown if there is an error
     *                                   downloading the file
     * @throws TooManyRequestsException  thrown when a 429 is received
     * @throws ResourceNotFoundException thrown when a 404 is received
     */
    public String fetchContent(URL url, Charset charset) throws DownloadFailedException, TooManyRequestsException, ResourceNotFoundException {
        return fetchContent(url, true, charset);
    }

    /**
     * Retrieves a file from a given URL and returns the contents.
     *
     * @param url      the URL of the file to download
     * @param useProxy whether to use the configured proxy when downloading
     *                 files
     * @param charset  The characterset to use to interpret the binary content of the file
     * @return the content of the file
     * @throws DownloadFailedException   is thrown if there is an error
     *                                   downloading the file
     * @throws TooManyRequestsException  thrown when a 429 is received
     * @throws ResourceNotFoundException thrown when a 404 is received
     */
    public String fetchContent(URL url, boolean useProxy, Charset charset)
            throws DownloadFailedException, TooManyRequestsException, ResourceNotFoundException {
        try {
            final String result;
            if ("file".equals(url.getProtocol())) {
                final Path p = Paths.get(url.toURI());
                result = Files.readString(p, charset);
            } else {
                final BasicClassicHttpRequest req;
                req = new BasicClassicHttpRequest(Method.GET, url.toURI());
                try (CloseableHttpClient hc = useProxy ? httpClientBuilder.build() : httpClientBuilderExplicitNoproxy.build()) {
                    req.addHeader(HttpHeaders.ACCEPT_CHARSET, charset.name());
                    final ExplicitCharsetToStringResponseHandler responseHandler = new ExplicitCharsetToStringResponseHandler(charset);
                    result = hc.execute(req, getPreEmptiveAuthContext(), responseHandler);
                }
            }
            return result;
        } catch (HttpResponseException hre) {
            wrapAndThrowHttpResponseException(url.toString(), hre);
            throw new InternalError("wrapAndThrowHttpResponseException will always throw an exception but Java compiler fails to spot it");
        } catch (RuntimeException | URISyntaxException | IOException ex) {
            final String msg = format("Download failed, error downloading '%s'; %s", url, ex.getMessage());
            throw new DownloadFailedException(msg, ex);
        }
    }

    /**
     * Gets a HttpClientContext that supports pre-emptive authentication.
     * @return A HttpClientContext pre-configured with the authentication cache build from the settings.
     */
    public HttpClientContext getPreEmptiveAuthContext() {
        final HttpClientContext context = HttpClientContext.create();
        context.setCredentialsProvider(credentialsProvider);
        context.setAuthCache(authCache);
        return context;
    }

    /**
     * Gets a pre-configured HttpClient.
     * Mainly targeted for use in paged resultset scenarios with multiple roundtrips.
     * @param useProxy Whether to use the configuration that includes proxy-settings
     * @return A HttpClient pre-configured with the settings.
     */
    public CloseableHttpClient getHttpClient(boolean useProxy) {
        return useProxy ? httpClientBuilder.build() : httpClientBuilderExplicitNoproxy.build();
    }

    /**
     * Download a resource from the given URL and have its content handled by the given ResponseHandler.
     *
     * @param url             The url of the resource
     * @param handler   The responsehandler to handle the response
     * @param <T>             The return-type for the responseHandler
     * @return The response handler result
     * @throws IOException               on I/O Exceptions
     * @throws TooManyRequestsException  When HTTP status 429 is encountered
     * @throws ResourceNotFoundException When HTTP status 404 is encountered
     */
    public <T> T fetchAndHandle(@NotNull URL url, @NotNull HttpClientResponseHandler<T> handler)
            throws IOException, TooManyRequestsException, ResourceNotFoundException, URISyntaxException {
        return fetchAndHandle(url, handler, Collections.emptyList(), true);
    }

    /**
     * Download a resource from the given URL and have its content handled by the given ResponseHandler.
     *
     * @param url               The url of the resource
     * @param handler   The responsehandler to handle the response
     * @param hdr Additional headers to add to the HTTP request
     * @param <T>               The return-type for the responseHandler
     * @return The response handler result
     * @throws IOException               on I/O Exceptions
     * @throws TooManyRequestsException  When HTTP status 429 is encountered
     * @throws ResourceNotFoundException When HTTP status 404 is encountered
     */
    public <T> T fetchAndHandle(@NotNull URL url, @NotNull HttpClientResponseHandler<T> handler, @NotNull List<Header> hdr)
            throws IOException, TooManyRequestsException, ResourceNotFoundException, URISyntaxException {
        return fetchAndHandle(url, handler, hdr, true);
    }

    /**
     * Download a resource from the given URL and have its content handled by the given ResponseHandler.
     *
     * @param url               The url of the resource
     * @param handler   The responsehandler to handle the response
     * @param hdr Additional headers to add to the HTTP request
     * @param useProxy          Whether to use the configured proxy for the connection
     * @param <T>               The return-type for the responseHandler
     * @return The response handler result
     * @throws IOException               on I/O Exceptions
     * @throws TooManyRequestsException  When HTTP status 429 is encountered
     * @throws ResourceNotFoundException When HTTP status 404 is encountered
     */
    public <T> T fetchAndHandle(@NotNull URL url, @NotNull HttpClientResponseHandler<T> handler, @NotNull List<Header> hdr, boolean useProxy)
            throws IOException, TooManyRequestsException, ResourceNotFoundException, URISyntaxException {
        final T data;
        if ("file".equals(url.getProtocol())) {
            final Path p = Paths.get(url.toURI());
            try (InputStream is = Files.newInputStream(p)) {
                final HttpEntity dummyEntity = new BasicHttpEntity(is, ContentType.APPLICATION_JSON);
                final ClassicHttpResponse dummyResponse = new BasicClassicHttpResponse(200);
                dummyResponse.setEntity(dummyEntity);
                data = handler.handleResponse(dummyResponse);
            } catch (HttpException e) {
                throw new IllegalStateException("HttpException encountered emulating a HTTP response from a file", e);
            }
        } else {
            try (CloseableHttpClient hc = useProxy ? httpClientBuilder.build() : httpClientBuilderExplicitNoproxy.build()) {
                return fetchAndHandle(hc, url, handler, hdr);
            }
        }
        return data;
    }
    /**
     * Download a resource from the given URL and have its content handled by the given ResponseHandler.
     *
     * @param client            The HTTP Client to reuse for the request
     * @param url               The url of the resource
     * @param handler   The responsehandler to handle the response
     * @param hdr Additional headers to add to the HTTP request
     * @param <T>               The return-type for the responseHandler
     * @return The response handler result
     * @throws IOException               on I/O Exceptions
     * @throws TooManyRequestsException  When HTTP status 429 is encountered
     * @throws ResourceNotFoundException When HTTP status 404 is encountered
     */
    public <T> T fetchAndHandle(@NotNull CloseableHttpClient client, @NotNull URL url, @NotNull HttpClientResponseHandler<T> handler, @NotNull List<Header> hdr)
            throws IOException, TooManyRequestsException, ResourceNotFoundException {
        try {
            final String theProtocol = url.getProtocol();
            if (!("http".equals(theProtocol) || "https".equals(theProtocol))) {
                throw new DownloadFailedException("Unsupported protocol in the URL; only http and https are supported");
            }
            final BasicClassicHttpRequest req = new BasicClassicHttpRequest(Method.GET, url.toURI());
            for (Header h : hdr) {
                req.addHeader(h);
            }
            final HttpClientContext context = getPreEmptiveAuthContext();
            return client.execute(req, context, handler);
        } catch (HttpResponseException hre) {
            final String messageFormat = "%s - Server status: %d - Server reason: %s";
            switch (hre.getStatusCode()) {
                case 404:
                    throw new ResourceNotFoundException(String.format(messageFormat, url, hre.getStatusCode(), hre.getReasonPhrase()));
                case 429:
                    throw new TooManyRequestsException(String.format(messageFormat, url, hre.getStatusCode(), hre.getReasonPhrase()));
                default:
                    throw new IOException(String.format(messageFormat, url, hre.getStatusCode(), hre.getReasonPhrase()));
            }
        } catch (RuntimeException | URISyntaxException ex) {
            final String msg = format("Download failed, unable to retrieve and parse '%s'; %s", url, ex.getMessage());
            throw new IOException(msg, ex);
        }
    }

    private static class SelectiveProxySelector extends ProxySelector {

        /**
         * The suffix-match entries from the nonProxyHosts (those starting with a {@code *}).
         */
        private final List<String> suffixMatch = new ArrayList<>();
        /**
         * The full host entries from the nonProxyHosts (those <em>not</em> starting with a {@code *}).
         */
        private final List<String> fullmatch = new ArrayList<>();
        /**
         * The proxy use when no proxy-exception is found.
         */
        private final Proxy configuredProxy;

        SelectiveProxySelector(Proxy httpHost, String[] nonProxyHostsPatterns) {
            for (String nonProxyHostPattern : nonProxyHostsPatterns) {
                if (nonProxyHostPattern.startsWith("*")) {
                    suffixMatch.add(nonProxyHostPattern.substring(1));
                } else {
                    fullmatch.add(nonProxyHostPattern);
                }
            }
            this.configuredProxy = httpHost;
        }

        @Override
        public List<Proxy> select(URI uri) {
            final String theHost = uri.getHost();
            if (fullmatch.contains(theHost)) {
                return Collections.singletonList(Proxy.NO_PROXY);
            } else {
                for (String suffix : suffixMatch) {
                    if (theHost.endsWith(suffix)) {
                        return Collections.singletonList(Proxy.NO_PROXY);
                    }
                }
            }
            return List.of(configuredProxy);
        }

        @Override
        public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
            // nothing to be done for this single proxy proxy-selector
        }
    }
}
