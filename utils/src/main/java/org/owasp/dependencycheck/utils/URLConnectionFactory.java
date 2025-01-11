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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URL;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * A URLConnection Factory to create new connections. This encapsulates several
 * configuration checks to ensure that the connection uses the correct proxy
 * settings.
 *
 * @author Jeremy Long
 */
public final class URLConnectionFactory {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(URLConnectionFactory.class);
    /**
     * The configured settings.
     */
    private final Settings settings;

    /**
     * Private constructor for this factory.
     *
     * @param settings reference to the configured settings
     */
    public URLConnectionFactory(Settings settings) {
        this.settings = settings;
    }

    /**
     * Utility method to create an HttpURLConnection. If the application is
     * configured to use a proxy this method will retrieve the proxy settings
     * and use them when setting up the connection.
     *
     * @param url the URL to connect to
     * @return an HttpURLConnection
     * @throws org.owasp.dependencycheck.utils.URLConnectionFailureException
     * thrown if there is an exception
     */
    @SuppressWarnings("squid:S2583")
    @SuppressFBWarnings(justification = "yes, there is a redundant null check in the catch - to suppress warnings we are leaving the null check",
            value = {"RCN_REDUNDANT_NULLCHECK_OF_NULL_VALUE"})
    public HttpURLConnection createHttpURLConnection(URL url) throws URLConnectionFailureException {
        HttpURLConnection conn = null;
        final String proxyHost = settings.getString(Settings.KEYS.PROXY_SERVER);

        try {
            if (proxyHost != null && !matchNonProxy(url)) {
                final int proxyPort = settings.getInt(Settings.KEYS.PROXY_PORT);
                final SocketAddress address = new InetSocketAddress(proxyHost, proxyPort);

                final String username = settings.getString(Settings.KEYS.PROXY_USERNAME);
                final String password = settings.getString(Settings.KEYS.PROXY_PASSWORD);

                if (username != null && password != null) {
                    final Authenticator auth = new Authenticator() {
                        @Override
                        public PasswordAuthentication getPasswordAuthentication() {
                            if (proxyHost.equals(getRequestingHost()) || getRequestorType().equals(Authenticator.RequestorType.PROXY)) {
                                LOGGER.debug("Using the configured proxy username and password");
                                if (settings.getBoolean(Settings.KEYS.PROXY_DISABLE_SCHEMAS, true)) {
                                    System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
                                }
                                return new PasswordAuthentication(username, password.toCharArray());
                            }
                            return super.getPasswordAuthentication();
                        }
                    };
                    Authenticator.setDefault(auth);
                }

                final Proxy proxy = new Proxy(Proxy.Type.HTTP, address);
                conn = (HttpURLConnection) url.openConnection(proxy);
            } else {
                conn = (HttpURLConnection) url.openConnection();
            }
            final int connectionTimeout = settings.getInt(Settings.KEYS.CONNECTION_TIMEOUT, 10000);
            // set a conservative long default timeout to compensate for MITM-proxies that return the (final) bytes only
            // after all security checks passed
            final int readTimeout = settings.getInt(Settings.KEYS.CONNECTION_READ_TIMEOUT, 60_000);
            conn.setConnectTimeout(connectionTimeout);
            conn.setReadTimeout(readTimeout);
            conn.setInstanceFollowRedirects(true);
        } catch (IOException ex) {
            if (conn != null) {
                try {
                    conn.disconnect();
                } finally {
                    conn = null;
                }
            }
            throw new URLConnectionFailureException("Error getting connection.", ex);
        }
        addAuthenticationIfPresent(conn);
        return conn;
    }

    /**
     * Adds the basic authorization header if the URL contains a username and
     * password. Example URL that will have the basic authorization header
     * added:
     * <code>http://username:password@passwordprotectednvdsite.internal/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz</code>
     *
     * @param conn the connection
     */
    private void addAuthenticationIfPresent(HttpURLConnection conn) {
        final String userInfo = conn.getURL().getUserInfo();
        if (userInfo != null) {
            final String basicAuth = "Basic " + Base64.getEncoder().encodeToString(userInfo.getBytes(UTF_8));
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Adding user info as basic authorization");
            }
            conn.addRequestProperty("Authorization", basicAuth);
        }
    }

    /**
     * Adds a basic authentication header if the values in the settings are not
     * null.
     *
     * @param conn the connection to add the basic auth header
     * @param userKey the settings key for the username
     * @param passwordKey the settings key for the password
     */
    public void addBasicAuthentication(HttpURLConnection conn, String userKey, String passwordKey) {
        if (StringUtils.isNotEmpty(settings.getString(userKey))
                && StringUtils.isNotEmpty(settings.getString(passwordKey))) {
            final String user = settings.getString(userKey);
            final String password = settings.getString(passwordKey);

            if (user.isEmpty() || password.isEmpty()) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Skip authentication as user and/or password is empty");
                }
            } else {
                final String userColonPassword = user + ":" + password;
                final String basicAuth = "Basic " + Base64.getEncoder().encodeToString(userColonPassword.getBytes(UTF_8));
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Adding user/password from settings.xml as basic authorization");
                }
                conn.addRequestProperty("Authorization", basicAuth);
            }
        }
    }

    /**
     * Check if host name matches nonProxy settings
     *
     * @param url the URL to connect to
     * @return matching result. true: match nonProxy
     */
    @SuppressWarnings("StringSplitter")
    private boolean matchNonProxy(final URL url) {
        final String host = url.getHost();

        // code partially from org.apache.maven.plugins.site.AbstractDeployMojo#getProxyInfo
        final String nonProxyHosts = settings.getString(Settings.KEYS.PROXY_NON_PROXY_HOSTS);
        if (null != nonProxyHosts) {
            final String[] nonProxies = nonProxyHosts.split("(,)|(;)|(\\|)");
            for (final String nonProxyHost : nonProxies) {
                //if ( StringUtils.contains( nonProxyHost, "*" ) )
                if (null != nonProxyHost && nonProxyHost.contains("*")) {
                    // Handle wildcard at the end, beginning or middle of the nonProxyHost
                    final int pos = nonProxyHost.indexOf('*');
                    final String nonProxyHostPrefix = nonProxyHost.substring(0, pos);
                    final String nonProxyHostSuffix = nonProxyHost.substring(pos + 1);
                    // prefix*
                    if (!StringUtils.isBlank(nonProxyHostPrefix) && host.startsWith(nonProxyHostPrefix) && StringUtils.isBlank(nonProxyHostSuffix)) {
                        return true;
                    }
                    // *suffix
                    if (StringUtils.isBlank(nonProxyHostPrefix) && !StringUtils.isBlank(nonProxyHostSuffix) && host.endsWith(nonProxyHostSuffix)) {
                        return true;
                    }
                    // prefix*suffix
                    if (!StringUtils.isBlank(nonProxyHostPrefix) && host.startsWith(nonProxyHostPrefix) && !StringUtils.isBlank(nonProxyHostSuffix)
                            && host.endsWith(nonProxyHostSuffix)) {
                        return true;
                    }
                } else if (host.equals(nonProxyHost)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Utility method to create an HttpURLConnection. The use of a proxy here is
     * optional as there may be cases where a proxy is configured but we don't
     * want to use it (for example, if there's an internal repository
     * configured)
     *
     * @param url the URL to connect to
     * @param proxy whether to use the proxy (if configured)
     * @return a newly constructed HttpURLConnection
     * @throws org.owasp.dependencycheck.utils.URLConnectionFailureException
     * thrown if there is an exception
     */
    public HttpURLConnection createHttpURLConnection(URL url, boolean proxy) throws URLConnectionFailureException {
        if (proxy) {
            return createHttpURLConnection(url);
        }
        final HttpURLConnection conn;
        try {
            conn = (HttpURLConnection) url.openConnection();
            final int timeout = settings.getInt(Settings.KEYS.CONNECTION_TIMEOUT, 10000);
            conn.setConnectTimeout(timeout);
            conn.setInstanceFollowRedirects(true);
        } catch (IOException ioe) {
            throw new URLConnectionFailureException("Error getting connection.", ioe);
        }
        addAuthenticationIfPresent(conn);
        return conn;
    }

}
