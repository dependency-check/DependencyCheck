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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.pom;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import javax.annotation.concurrent.ThreadSafe;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import org.apache.commons.io.ByteOrderMark;
import org.apache.commons.io.input.BOMInputStream;
import org.owasp.dependencycheck.utils.XmlUtils;
import org.owasp.dependencycheck.xml.XmlInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

/**
 * A parser for pom.xml files.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class PomParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(PomParser.class);

    /**
     * Parses the given xml file and returns a Model object containing only the
     * fields dependency-check requires. An attempt is made to remove any
     * doctype definitions.
     *
     * @param file a pom.xml
     * @return a Model object containing only the fields dependency-check
     * requires
     * @throws PomParseException thrown if the xml file cannot be parsed
     */
    public Model parse(File file) throws PomParseException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return parse(fis);
        } catch (IOException ex) {
            if (ex instanceof PomParseException) {
                throw (PomParseException) ex;
            }
            LOGGER.debug("", ex);
            throw new PomParseException(String.format("Unable to parse pom '%s'", file), ex);
        }
    }

    /**
     * Parses the given xml file and returns a Model object containing only the
     * fields dependency-check requires. No attempt is made to remove doctype
     * definitions.
     *
     * @param file a pom.xml
     * @return a Model object containing only the fields dependency-check
     * requires
     * @throws PomParseException thrown if the xml file cannot be parsed
     */
    public Model parseWithoutDocTypeCleanup(File file) throws PomParseException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return parseWithoutDocTypeCleanup(fis);
        } catch (IOException ex) {
            if (ex instanceof PomParseException) {
                throw (PomParseException) ex;
            }
            LOGGER.debug("", ex);
            throw new PomParseException(String.format("Unable to parse pom '%s'", file), ex);
        }
    }

    /**
     * Parses the given XML file and returns a Model object containing only the
     * fields dependency-check requires. An attempt is made to remove any
     * doctype definitions.
     *
     * @param inputStream an InputStream containing suppression rues
     * @return a list of suppression rules
     * @throws PomParseException if the XML cannot be parsed
     */
    public Model parse(InputStream inputStream) throws PomParseException {
        try {
            final PomHandler handler = new PomHandler();
            final SAXParser saxParser = XmlUtils.buildSecureSaxParser();
            final XMLReader xmlReader = saxParser.getXMLReader();
            xmlReader.setContentHandler(handler);

            final BOMInputStream bomStream = BOMInputStream.builder()
                    .setInputStream(new XmlInputStream(new PomProjectInputStream(inputStream))).get();
            final ByteOrderMark bom = bomStream.getBOM();
            final String defaultEncoding = StandardCharsets.UTF_8.name();
            final String charsetName = bom == null ? defaultEncoding : bom.getCharsetName();
            final Reader reader = new InputStreamReader(bomStream, charsetName);
            final InputSource in = new InputSource(reader);
            xmlReader.parse(in);
            return handler.getModel();
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            LOGGER.debug("", ex);
            throw new PomParseException(ex);
        }
    }

    /**
     * Parses the given XML file and returns a Model object containing only the
     * fields dependency-check requires. No attempt is made to remove doctype
     * definitions.
     *
     * @param inputStream an InputStream containing suppression rues
     * @return a list of suppression rules
     * @throws PomParseException if the XML cannot be parsed
     */
    public Model parseWithoutDocTypeCleanup(InputStream inputStream) throws PomParseException {
        try {
            final PomHandler handler = new PomHandler();
            final SAXParser saxParser = XmlUtils.buildSecureSaxParser();
            final XMLReader xmlReader = saxParser.getXMLReader();
            xmlReader.setContentHandler(handler);

            final BOMInputStream bomStream = BOMInputStream.builder().setInputStream(new XmlInputStream(inputStream)).get();
            final ByteOrderMark bom = bomStream.getBOM();
            final String defaultEncoding = StandardCharsets.UTF_8.name();
            final String charsetName = bom == null ? defaultEncoding : bom.getCharsetName();
            final Reader reader = new InputStreamReader(bomStream, charsetName);
            final InputSource in = new InputSource(reader);
            xmlReader.parse(in);
            return handler.getModel();
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            LOGGER.debug("", ex);
            throw new PomParseException(ex);
        }
    }
}
