/*
 * This file is part of dependency-check-core.
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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.ossindex;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.message.BasicHeader;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import org.sonatype.ossindex.service.client.OssindexClientConfiguration;
import org.sonatype.ossindex.service.client.transport.BasicAuthHelper;
import org.sonatype.ossindex.service.client.transport.Transport;
import org.sonatype.ossindex.service.client.transport.UserAgentSupplier;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * ODC connection transport is used instead of HttpUrlConnectionTransport
 * because the proxy information is already configured.
 *
 * @author Jeremy Long
 */
public class ODCConnectionTransport implements Transport {

    /**
     * The OSS Index client configuration.
     */
    private final OssindexClientConfiguration configuration;
    /**
     * The user agent to send in the HTTP connection.
     */
    private final UserAgentSupplier userAgent;

    /**
     * Constructs a new transport object to connect to the OSS Index.
     *
     * @param config the OSS client configuration
     * @param userAgent the user agent to send to OSS Index
     */
    public ODCConnectionTransport(OssindexClientConfiguration config, UserAgentSupplier userAgent) {
        this.userAgent = userAgent;
        this.configuration = config;
    }

    @Override
    public void init(OssindexClientConfiguration configuration) {
        // no initialisation needed
    }

    @Override
    public String post(URI url, String payloadType, String payload, String acceptType) throws TransportException, IOException {
        try {
            final List<Header> headers = new ArrayList<>(3);
            headers.add(new BasicHeader(HttpHeaders.ACCEPT, acceptType));
            headers.add(new BasicHeader(HttpHeaders.USER_AGENT, userAgent.get()));
            // TODO consider to promote pre-emptive authentication by default to the Downloader and also load the OSSIndex credentials there.
            final String authorization = BasicAuthHelper.authorizationHeader(configuration.getAuthConfiguration());
            if (authorization != null) {
                headers.add(new BasicHeader(HttpHeaders.AUTHORIZATION, authorization));
            }
            return Downloader.getInstance().postBasedFetchContent(url, payload, ContentType.create(payloadType, StandardCharsets.UTF_8), headers);
        } catch (TooManyRequestsException e) {
            throw new TransportException("Too many requests for " + url.toString() + " HTTP status 429", e);
        } catch (ResourceNotFoundException e) {
            throw new TransportException("Not found for " + url.toString() + "HTTP status 404", e);
        }
    }

    @Override
    public void close() throws Exception {
        // no resource closure needed; fully delegated to HTTPClient
    }

    UserAgentSupplier getUserAgent() {
        return userAgent;
    }
}
