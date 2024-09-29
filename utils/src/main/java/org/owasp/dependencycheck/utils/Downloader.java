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
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.CredentialsStore;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
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

        final SystemDefaultCredentialsProvider credentialsProvider = new SystemDefaultCredentialsProvider();
        if (settings.getString(Settings.KEYS.PROXY_SERVER) != null) {
            // Legacy proxy configuration present
            // So don't rely on the system properties for proxy; use the legacy settings configuration
            final String proxyHost = settings.getString(Settings.KEYS.PROXY_SERVER);
            final int proxyPort = settings.getInt(Settings.KEYS.PROXY_PORT, -1);
            httpClientBuilder.setProxy(new HttpHost(proxyHost, proxyPort));
            if (settings.getString(Settings.KEYS.PROXY_USERNAME) != null) {
                final String proxyuser = settings.getString(Settings.KEYS.PROXY_USERNAME);
                final char[] proxypass = settings.getString(Settings.KEYS.PROXY_PASSWORD).toCharArray();
                credentialsProvider.setCredentials(
                        new AuthScope(null, proxyHost, proxyPort, null, null),
                        new UsernamePasswordCredentials(proxyuser, proxypass)
                );
            }
        }
        tryAddRetireJSCredentials(settings, credentialsProvider);
        tryAddHostedSuppressionCredentials(settings, credentialsProvider);
        tryAddKEVCredentials(settings, credentialsProvider);
        tryAddNexusAnalyzerCredentials(settings, credentialsProvider);
        tryAddNVDApiDatafeed(settings, credentialsProvider);
        httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
        httpClientBuilderExplicitNoproxy.setDefaultCredentialsProvider(credentialsProvider);
    }

    private void tryAddRetireJSCredentials(Settings settings, CredentialsStore credentialsStore) throws InvalidSettingException {
        if (settings.getString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_PASSWORD) != null) {
            addUserPasswordCreds(settings, credentialsStore,
                    Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_USER,
                    Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL,
                    Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_PASSWORD,
                    "RetireJS repo.js");
        }
    }

    private void tryAddHostedSuppressionCredentials(Settings settings, CredentialsStore credentialsStore) throws InvalidSettingException {
        if (settings.getString(Settings.KEYS.HOSTED_SUPPRESSIONS_PASSWORD) != null) {
            addUserPasswordCreds(settings, credentialsStore,
                    Settings.KEYS.HOSTED_SUPPRESSIONS_USER,
                    Settings.KEYS.HOSTED_SUPPRESSIONS_URL,
                    Settings.KEYS.HOSTED_SUPPRESSIONS_PASSWORD,
                    "Hosted suppressions");
        }
    }

    private void tryAddKEVCredentials(Settings settings, CredentialsStore credentialsStore) throws InvalidSettingException {
        if (settings.getString(Settings.KEYS.KEV_PASSWORD) != null) {
            addUserPasswordCreds(settings, credentialsStore,
                    Settings.KEYS.KEV_USER,
                    Settings.KEYS.KEV_URL,
                    Settings.KEYS.KEV_PASSWORD,
                    "Known Exploited Vulnerabilities");
        }
    }

    private void tryAddNexusAnalyzerCredentials(Settings settings, CredentialsStore credentialsStore) throws InvalidSettingException {
        if (settings.getString(Settings.KEYS.ANALYZER_NEXUS_PASSWORD) != null) {
            addUserPasswordCreds(settings, credentialsStore,
                    Settings.KEYS.ANALYZER_NEXUS_URL,
                    Settings.KEYS.ANALYZER_NEXUS_USER,
                    Settings.KEYS.ANALYZER_NEXUS_PASSWORD,
                    "Nexus Analyzer");
        }
    }

    private void tryAddNVDApiDatafeed(Settings settings, CredentialsStore credentialsStore) throws InvalidSettingException {
        if (settings.getString(Settings.KEYS.NVD_API_DATAFEED_PASSWORD) != null) {
            addUserPasswordCreds(settings, credentialsStore,
                    Settings.KEYS.NVD_API_DATAFEED_URL,
                    Settings.KEYS.NVD_API_DATAFEED_USER,
                    Settings.KEYS.NVD_API_DATAFEED_PASSWORD,
                    "NVD API Datafeed");
        }
    }

    /**
     * Add user/password credentials for the host/port of the URL, all configured in the settings, to the credential-store.
     *
     * @param settings The settings to retrieve the values from
     * @param store The credentialStore
     * @param userKey The key for a configured username credential part
     * @param passwordKey The key for a configured password credential part
     * @param urlKey The key for a configured url for which the credentials hold
     * @param desc A descriptive text for use in error messages for this credential
     * @throws InvalidSettingException When the password is empty or one of the other keys are not found in the settings.
     */
    private void addUserPasswordCreds(Settings settings, CredentialsStore store, String userKey, String urlKey, String passwordKey, String desc)
            throws InvalidSettingException {
        final String theUser = settings.getString(userKey);
        final String theURL = settings.getString(urlKey);
        final char[] thePass = settings.getString(passwordKey, "").toCharArray();
        if (theUser == null || theURL == null || thePass.length == 0) {
            throw new InvalidSettingException(desc + " URL and username are required when setting " + desc + " password");
        }
        try {
            final URL parsedURL = new URL(theURL);
            addCredentials(store, desc, parsedURL, theUser, thePass);
        } catch (MalformedURLException e) {
            throw new InvalidSettingException(desc + " URL must be a valid URL", e);
        }
    }

    private static void addCredentials(CredentialsStore credentialsStore, String messageScope, URL parsedURL, String theUser, char[] thePass)
            throws InvalidSettingException {
        final String theProtocol = parsedURL.getProtocol();
        if ("file".equals(theProtocol)) {
            LOGGER.warn("Credentials are not supported for file-protocol, double-check your configuration options for {}.", messageScope);
            return;
        } else if ("http".equals(theProtocol)) {
            LOGGER.warn("Insecure configuration: Basic Credentials are configured to be used over a plain http connection for {}. "
                    + "Consider migrating to https to guard the credentials.", messageScope);
        } else if (!"https".equals(theProtocol)) {
            throw new InvalidSettingException("Unsupported protocol in the " + messageScope
                    + " URL; only file, http and https are supported");
        }
        final String theHost = parsedURL.getHost();
        final int thePort = parsedURL.getPort();
        final Credentials creds = new UsernamePasswordCredentials(theUser, thePass);
        final AuthScope scope = new AuthScope(theProtocol, theHost, thePort, null, null);
        credentialsStore.setCredentials(scope, creds);
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
                    hc.execute(req, responseHandler);
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
            final HttpClientContext context = HttpClientContext.create();
            final BasicCredentialsProvider localCredentials = new BasicCredentialsProvider();
            addCredentials(localCredentials, url.toString(), url, settings.getString(userKey), settings.getString(passwordKey).toCharArray());
            context.setCredentialsProvider(localCredentials);
            try (CloseableHttpClient hc = useProxy ? httpClientBuilder.build() : httpClientBuilderExplicitNoproxy.build()) {
                final BasicClassicHttpRequest req = new BasicClassicHttpRequest(Method.GET, url.toURI());
                final SaveToFileResponseHandler responseHandler = new SaveToFileResponseHandler(outputPath);
                hc.execute(req, context, responseHandler);
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
                    result = hc.execute(req, new BasicHttpClientResponseHandler());
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
                    final ExplicitEncodingToStringResponseHandler responseHandler = new ExplicitEncodingToStringResponseHandler(charset);
                    result = hc.execute(req, responseHandler);
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
            throws IOException, TooManyRequestsException, ResourceNotFoundException {
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
            throws IOException, TooManyRequestsException, ResourceNotFoundException {
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
            throws IOException, TooManyRequestsException, ResourceNotFoundException {
        try {
            final T data;
            if ("file".equals(url.getProtocol())) {
                final Path p = Paths.get(url.toURI());
                try (InputStream is = Files.newInputStream(p)) {
                    final HttpEntity dummyEntity = new BasicHttpEntity(is, ContentType.APPLICATION_JSON);
                    final ClassicHttpResponse dummyResponse = new BasicClassicHttpResponse(200);
                    dummyResponse.setEntity(dummyEntity);
                    data = handler.handleResponse(dummyResponse);
                } catch (HttpException e) {
                    throw new IllegalStateException("HttpException encountered without HTTP traffic", e);
                }
            } else {
                final String theProtocol = url.getProtocol();
                if (!("http".equals(theProtocol) || "https".equals(theProtocol))) {
                    throw new DownloadFailedException("Unsupported protocol in the URL; only file, http and https are supported");
                }
                try (CloseableHttpClient hc = useProxy ? httpClientBuilder.build() : httpClientBuilderExplicitNoproxy.build()) {
                    final BasicClassicHttpRequest req = new BasicClassicHttpRequest(Method.GET, url.toURI());
                    for (Header h : hdr) {
                        req.addHeader(h);
                    }
                    data = hc.execute(req, handler);
                }
            }
            return data;
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
}
