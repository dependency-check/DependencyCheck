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

import org.apache.hc.client5.http.auth.AuthCache;
import org.apache.hc.client5.http.auth.AuthChallenge;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.AuthenticationException;
import org.apache.hc.client5.http.auth.BearerToken;
import org.apache.hc.client5.http.auth.ChallengeType;
import org.apache.hc.client5.http.auth.CredentialsStore;
import org.apache.hc.client5.http.auth.MalformedChallengeException;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.auth.BasicScheme;
import org.apache.hc.client5.http.impl.auth.BearerScheme;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.HttpHost;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;

public final class HC5CredentialHelper {
    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(HC5CredentialHelper.class);

    private HC5CredentialHelper() {
        // Hide utility class constructor
    }


    /**
     * Configure pre-emptive Bearer Auth for the host of the URL.
     *
     * @param theURL           The URL to be authenticated by HTTP Bearer auth
     * @param theToken         The token for Bearer auth
     * @param credentialsStore The credential store that will be set in the HTTP clients context
     * @param authCache        The authentication cache that will be set in the HTTP clients context
     */
    public static void configurePreEmptiveBearerAuth(URL theURL, String theToken, CredentialsStore credentialsStore, AuthCache authCache) {
        final HttpHost scopeHost = new HttpHost(theURL.getProtocol(), theURL.getHost(), theURL.getPort());
        final BearerToken creds = new BearerToken(theToken);
        final AuthScope scope = new AuthScope(scopeHost, null, null);
        credentialsStore.setCredentials(scope, creds);
        final BearerScheme bearerAuth = new BearerScheme();
        try {
            final AuthChallenge preemtiveAuthDummyChallenge = new AuthChallenge(ChallengeType.TARGET, scopeHost.getSchemeName());
            final HttpClientContext preEmptiveAuthDummyContext = new HttpClientContext();
            bearerAuth.processChallenge(preemtiveAuthDummyChallenge, preEmptiveAuthDummyContext);
            if (!bearerAuth.isResponseReady(scopeHost, credentialsStore, preEmptiveAuthDummyContext)) {
                LOGGER.warn("Bearer Credentials failed to be be pre-empted for {}", theURL);
            }
            authCache.put(scopeHost, bearerAuth);
        } catch (AuthenticationException | MalformedChallengeException e) {
            LOGGER.warn("Bearer Credentials failed to be be pre-empted for {}", theURL, e);
        }
    }

    /**
     * Configure pre-emptive Basic Auth for the host of the URL.
     *
     * @param theURL           The URL to be authenticated by HTTP Basic auth
     * @param theUser          The username for Basic auth
     * @param thePass          The password for Basic auth
     * @param credentialsStore The credential store that will be set in the HTTP clients context
     * @param authCache        The authentication cache that will be set in the HTTP clients context
     */
    public static void configurePreEmptiveBasicAuth(URL theURL, String theUser, String thePass, CredentialsStore credentialsStore,
                                                    AuthCache authCache) {
        final HttpHost scopeHost = new HttpHost(theURL.getProtocol(), theURL.getHost(), theURL.getPort());
        final UsernamePasswordCredentials creds = new UsernamePasswordCredentials(theUser, thePass.toCharArray());
        final AuthScope scope = new AuthScope(scopeHost, null, null);
        credentialsStore.setCredentials(scope, creds);
        final BasicScheme basicAuth = new BasicScheme();
        basicAuth.initPreemptive(creds);
        authCache.put(scopeHost, basicAuth);
    }
}
