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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.exception;

import javax.annotation.concurrent.ThreadSafe;

/**
 * An exception used when data corruption is detected on an NVD CVE Datastream file.
 *
 * @author Hans Aikema
 */
@ThreadSafe
public class CorruptedDatastreamException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Create a new CorruptedDatastreamException.
     */
    public CorruptedDatastreamException() {
    }

    /**
     * Create a new CorruptedDatastreamException with the specified detail message.
     *
     * @param message
     *         a message for the exception.
     */
    public CorruptedDatastreamException(final String message) {
        super(message);
    }

    /**
     * Create a new CorruptedDatastreamException with the specified cause.
     *
     * @param cause
     *         the cause for the exception.
     */
    public CorruptedDatastreamException(final Throwable cause) {
        super(cause);
    }

    /**
     * Create a new CorruptedDatastreamException with the specified detail message and cause.
     *
     * @param message
     *         a message for the exception.
     * @param cause
     *         the cause for the exception.
     */
    public CorruptedDatastreamException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
