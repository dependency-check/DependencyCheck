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
 * Copyright (c) 2016 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.hints;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.annotation.concurrent.NotThreadSafe;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import org.apache.commons.io.ByteOrderMark;
import org.apache.commons.io.input.BOMInputStream;

import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.XmlUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

/**
 * A simple validating parser for XML Hint Rules.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class HintParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(HintParser.class);
    /**
     * JAXP Schema Language. Source:
     * http://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html
     */
    public static final String JAXP_SCHEMA_LANGUAGE = "http://java.sun.com/xml/jaxp/properties/schemaLanguage";
    /**
     * W3C XML Schema. Source:
     * http://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html
     */
    public static final String W3C_XML_SCHEMA = "http://www.w3.org/2001/XMLSchema";
    /**
     * JAXP Schema Source. Source:
     * http://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html
     */
    public static final String JAXP_SCHEMA_SOURCE = "http://java.sun.com/xml/jaxp/properties/schemaSource";

    /**
     * The schema for the hint XML files.
     */
    private static final String HINT_SCHEMA_1_2 = "schema/dependency-hint.1.2.xsd";

    /**
     * The schema for the hint XML files.
     */
    private static final String HINT_SCHEMA_1_1 = "schema/dependency-hint.1.1.xsd";

    /**
     * The schema for the hint XML files.
     */
    private static final String HINT_SCHEMA_1_3 = "schema/dependency-hint.1.3.xsd";

    /**
     * The schema for the hint XML files.
     */
    private static final String HINT_SCHEMA_1_4 = "schema/dependency-hint.1.4.xsd";

    /**
     * The hint rules.
     */
    private List<HintRule> hintRules;
    /**
     * The vendor duplicating hint rules.
     */
    private List<VendorDuplicatingHintRule> vendorDuplicatingHintRules;

    /**
     * Returns the hint rules.
     *
     * @return the hint rules
     */
    @SuppressWarnings({"EI_EXPOSE_REP", "EI_EXPOSE_REP2"})
    public List<HintRule> getHintRules() {
        return hintRules;
    }

    /**
     * Returns the vendor duplicating hint rules.
     *
     * @return the vendor duplicating hint rules
     */
    public List<VendorDuplicatingHintRule> getVendorDuplicatingHintRules() {
        return vendorDuplicatingHintRules;
    }

    /**
     * Parses the given XML file and returns a list of the hints contained.
     *
     * @param file an XML file containing hints
     * @throws HintParseException thrown if the XML file cannot be parsed
     */
    @SuppressFBWarnings(justification = "try with resources will clean up the input stream", value = {"OBL_UNSATISFIED_OBLIGATION"})
    public void parseHints(File file) throws HintParseException {
        try (InputStream fis = new FileInputStream(file)) {
            parseHints(fis);
        } catch (SAXException | IOException ex) {
            LOGGER.debug("", ex);
            throw new HintParseException(ex);
        }
    }

    /**
     * Parses the given XML stream and returns a list of the hint rules
     * contained.
     *
     * @param inputStream an InputStream containing hint rules
     * @throws HintParseException thrown if the XML cannot be parsed
     * @throws SAXException thrown if the XML cannot be parsed
     */
    public void parseHints(InputStream inputStream) throws HintParseException, SAXException {
        try (
                InputStream schemaStream14 = FileUtils.getResourceAsStream(HINT_SCHEMA_1_4);
                InputStream schemaStream13 = FileUtils.getResourceAsStream(HINT_SCHEMA_1_3);
                InputStream schemaStream12 = FileUtils.getResourceAsStream(HINT_SCHEMA_1_2);
                InputStream schemaStream11 = FileUtils.getResourceAsStream(HINT_SCHEMA_1_1)) {

            final BOMInputStream bomStream = BOMInputStream.builder().setInputStream(inputStream).get();
            final ByteOrderMark bom = bomStream.getBOM();
            final String defaultEncoding = StandardCharsets.UTF_8.name();
            final String charsetName = bom == null ? defaultEncoding : bom.getCharsetName();

            final HintHandler handler = new HintHandler();
            final SAXParser saxParser = XmlUtils.buildSecureSaxParser(schemaStream14, schemaStream13, schemaStream12, schemaStream11);
            final XMLReader xmlReader = saxParser.getXMLReader();
            xmlReader.setErrorHandler(new HintErrorHandler());
            xmlReader.setContentHandler(handler);
            try (Reader reader = new InputStreamReader(bomStream, charsetName)) {
                final InputSource in = new InputSource(reader);
                xmlReader.parse(in);
                this.hintRules = handler.getHintRules();
                this.vendorDuplicatingHintRules = handler.getVendorDuplicatingHintRules();
            }
        } catch (ParserConfigurationException | IOException ex) {
            LOGGER.debug("", ex);
            throw new HintParseException(ex);
        } catch (SAXException ex) {
            if (ex.getMessage().contains("Cannot find the declaration of element 'hints'.")) {
                throw ex;
            } else {
                LOGGER.debug("", ex);
                throw new HintParseException(ex);
            }
        }
    }
}
