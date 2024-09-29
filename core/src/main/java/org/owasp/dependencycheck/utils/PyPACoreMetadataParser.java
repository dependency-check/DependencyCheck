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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Properties;

/**
 * A utility class to handle Python Packaging Authority (PyPA) core metadata files. It was created based on the
 * <a href="https://packaging.python.org/en/latest/specifications/core-metadata/">specification by PyPA</a> for
 * version 2.2
 *
 * @author Hans Aikema
 */
public final class PyPACoreMetadataParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(PyPACoreMetadataParser.class);

    /**
     * The largest major version considered by this parser
     */
    private static final int SUPPORTED_MAJOR_UPPERBOUND = 2;

    /**
     * The largest version of the specification considered during coding of this parser
     */
    private static final BigDecimal MAX_SUPPORTED_VERSION = BigDecimal.valueOf(22, 1);

    private PyPACoreMetadataParser() {
        // hide constructor for utility class
    }
    /**
     * Loads all key/value pairs from PyPA metadata specifications¶.
     *
     * @param file
     *         The Wheel metadata of a Python package as a File
     *
     * @return The metadata properties read from the file
     * @throws AnalysisException thrown if there is an analysis exception
     */
    public static Properties getProperties(File file) throws AnalysisException {
        try (BufferedReader utf8Reader = Files.newBufferedReader(file.toPath(), StandardCharsets.UTF_8)) {
            return getProperties(utf8Reader);
        } catch (IOException | IllegalArgumentException e) {
            throw new AnalysisException("Error parsing PyPA core-metadata file", e);
        }
    }

    /**
     * Loads all key/value pairs from PyPA metadata specifications¶.
     *
     * @param utf8Reader
     *         The Wheel metadata of a Python package as a BufferedReader
     *
     * @return The metadata properties read from the utf8Reader
     * @throws java.io.IOException thrown if there is error reading the properties
     */
    public static Properties getProperties(final BufferedReader utf8Reader) throws IOException {
        final Properties result = new Properties();
        String line = utf8Reader.readLine();
        StringBuilder singleHeader = null;
        boolean inDescription = false;
        while (line != null && !line.isEmpty()) {
            if (inDescription && line.startsWith("       |")) {
                singleHeader.append('\n').append(line.substring(8));
            } else if (singleHeader != null && line.startsWith(" ")) {
                singleHeader.append(line.substring(1));
            } else {
                if (singleHeader != null) {
                    parseAndAddHeader(result, singleHeader);
                }
                singleHeader = new StringBuilder(line);
                inDescription = line.startsWith("Description:");
            }
            line = utf8Reader.readLine();
        }
        if (singleHeader != null) {
            parseAndAddHeader(result, singleHeader);
        }
        // ignore a body if any (description is allowed to be the message body)
        return result;
    }

    /**
     * Add a single metadata keyvalue pair to the metadata. When the given metadataHeader cannot be parsed as a '{@code key: value}'
     * line a warning is emitted and the line is ignored.
     *
     * @param metadata
     *         The collected metadata to which the new metadataHeader must be added
     * @param metadataHeader
     *         A single uncollapsed header line of the metadata
     *
     * @throws IllegalArgumentException
     *         When the given metadataHeader has a key {@code Metadata-Version} and the value holds a major version that is larger
     *         than the highest supported metadata version. As defined by the specification: <blockquote>Automated tools consuming
     *         metadata SHOULD warn if metadata_version is greater than the highest version they support, and MUST fail if
     *         metadata_version has a greater major version than the highest version they support (as described in PEP 440, the
     *         major version is the value before the first dot).</blockquote>
     */
    private static void parseAndAddHeader(final Properties metadata, final StringBuilder metadataHeader) {
        final String[] keyValue = StringUtils.split(metadataHeader.toString(), ":", 2);
        if (keyValue.length != 2) {
            LOGGER.warn("Invalid mailheader format encountered in Wheel Metadata, not a \"key: value\" string");
            return;
        }
        final String key = keyValue[0];
        final String value = keyValue[1].trim();
        if ("Metadata-Version".equals(key)) {
            final int majorVersion = Integer.parseInt(value.substring(0, value.indexOf('.')), 10);
            final BigDecimal version = new BigDecimal(value);
            if (majorVersion > SUPPORTED_MAJOR_UPPERBOUND) {
                throw new IllegalArgumentException(String.format(
                        "Unsupported PyPA Wheel metadata. Metadata-Version " + "is '%s', largest supported major is %d", value,
                        SUPPORTED_MAJOR_UPPERBOUND));
            } else if (version.compareTo(MAX_SUPPORTED_VERSION) > 0 && LOGGER.isWarnEnabled()) {
                LOGGER.warn(String.format("Wheel metadata Metadata-Version (%s) has a larger minor version than the highest known "
                                          + "supported Metadata specification (%s) continuing with best effort", value,
                                          MAX_SUPPORTED_VERSION));
            }
        }
        metadata.setProperty(key, value);
    }
}
