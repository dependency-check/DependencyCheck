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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import javax.annotation.concurrent.ThreadSafe;
import java.time.Duration;

/**
 * An exception used when the server has blocked the requests due to too many requests.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class TooManyRequestsException extends Exception {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 4044042874643986535L;

    /**
     * How long the server asked the client to wait before retrying, from the
     * Retry-After header; null when the server did not say.
     */
    private final Duration retryAfter;

    /**
     * Creates a new TooManyRequestsException.
     */
    public TooManyRequestsException() {
        super();
        retryAfter = null;
    }

    /**
     * Creates a new TooManyRequestsException.
     *
     * @param msg a message for the exception.
     */
    public TooManyRequestsException(String msg) {
        super(msg);
        retryAfter = null;
    }

    /**
     * Creates a new TooManyRequestsException.
     *
     * @param ex the cause of the exception.
     */
    public TooManyRequestsException(Throwable ex) {
        super(ex);
        retryAfter = null;
    }

    /**
     * Creates a new TooManyRequestsException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the exception.
     */
    public TooManyRequestsException(String msg, Throwable ex) {
        super(msg, ex);
        retryAfter = null;
    }

    /**
     * Creates a new TooManyRequestsException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the exception.
     * @param retryAfter how long the server asked the client to wait before
     * retrying; null when the server did not say.
     */
    public TooManyRequestsException(String msg, Throwable ex, Duration retryAfter) {
        super(msg, ex);
        this.retryAfter = retryAfter;
    }

    /**
     * Returns how long the server asked the client to wait before retrying,
     * from the Retry-After header.
     *
     * @return the requested wait, or null when the server did not send a
     * usable Retry-After header
     */
    public Duration getRetryAfter() {
        return retryAfter;
    }
}
