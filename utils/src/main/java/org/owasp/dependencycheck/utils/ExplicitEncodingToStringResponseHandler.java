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

import org.apache.hc.client5.http.impl.classic.AbstractHttpClientResponseHandler;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;

import java.io.IOException;
import java.nio.charset.Charset;

/**
 * A responseHandler that uses an explicit client-defined characterset to interpret the response payload as a string.
 *
 * @author Hans Aikema
 */
public class ExplicitEncodingToStringResponseHandler extends AbstractHttpClientResponseHandler<String> {

    /**
     * The explicit Charset used for interpreting the bytes of the HTTP response entity.
     */
    private final Charset charset;

    /**
     * Constructs a repsonse handler to transfor the binary contents received using the given Charset.
     *
     * @param charset The Charset to be used to transform a downloaded file into a String.
     */
    public ExplicitEncodingToStringResponseHandler(Charset charset) {
        this.charset = charset;
    }

    @Override
    public String handleEntity(HttpEntity entity) throws IOException {
        return new String(EntityUtils.toByteArray(entity), charset);
    }
}
