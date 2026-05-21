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
package org.owasp.dependencycheck.xml.suppression;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.annotation.concurrent.ThreadSafe;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.ByteOrderMark;
import org.apache.commons.io.input.BOMInputStream;

import org.owasp.dependencycheck.utils.AutoCloseableInputSource;
import org.owasp.dependencycheck.utils.XmlUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import static org.owasp.dependencycheck.utils.AutoCloseableInputSource.fromResource;

/**
 * A simple validating parser for XML Suppression Rules.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class SuppressionParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SuppressionParser.class);

    /**
     * The suppression schema file location for v 1.4.
     */
    public static final String SUPPRESSION_SCHEMA_1_4 = "schema/dependency-suppression.1.4.xsd";
    /**
     * The suppression schema file location for v 1.3.
     */
    public static final String SUPPRESSION_SCHEMA_1_3 = "schema/dependency-suppression.1.3.xsd";
    /**
     * The suppression schema file location for v 1.2.
     */
    public static final String SUPPRESSION_SCHEMA_1_2 = "schema/dependency-suppression.1.2.xsd";
    /**
     * The suppression schema file location for v1.1.
     */
    public static final String SUPPRESSION_SCHEMA_1_1 = "schema/dependency-suppression.1.1.xsd";
    /**
     * The old suppression schema file location for v1.0.
     */
    private static final String SUPPRESSION_SCHEMA_1_0 = "schema/suppression.xsd";

    /**
     * Parses the given XML file and returns a list of the suppression rules
     * contained.
     *
     * @param file an XML file containing suppression rules
     * @return a list of suppression rules
     * @throws SuppressionParseException thrown if the XML file cannot be parsed
     */
    @SuppressFBWarnings(justification = "try with resource will clenaup the resources", value = {"OBL_UNSATISFIED_OBLIGATION"})
    public List<SuppressionRule> parseSuppressionRules(File file) throws SuppressionParseException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return parseSuppressionRules(fis);
        } catch (SAXException | IOException ex) {
            LOGGER.debug("", ex);
            throw new SuppressionParseException(ex);
        }
    }

    /**
     * Parses the given XML stream and returns a list of the suppression rules
     * contained.
     *
     * @param inputStream an InputStream containing suppression rules
     * @return a list of suppression rules
     * @throws SuppressionParseException thrown if the XML cannot be parsed
     * @throws SAXException thrown if the XML cannot be parsed
     */
    public List<SuppressionRule> parseSuppressionRules(InputStream inputStream)
            throws SuppressionParseException, SAXException {
        try (AutoCloseableInputSource schemaStream14 = fromResource(SUPPRESSION_SCHEMA_1_4);
             AutoCloseableInputSource schemaStream13 = fromResource(SUPPRESSION_SCHEMA_1_3);
             AutoCloseableInputSource schemaStream12 = fromResource(SUPPRESSION_SCHEMA_1_2);
             AutoCloseableInputSource schemaStream11 = fromResource(SUPPRESSION_SCHEMA_1_1);
             AutoCloseableInputSource schemaStream10 = fromResource(SUPPRESSION_SCHEMA_1_0)) {

            final BOMInputStream bomStream = BOMInputStream.builder().setInputStream(inputStream).get();
            final ByteOrderMark bom = bomStream.getBOM();
            final String defaultEncoding = StandardCharsets.UTF_8.name();
            final String charsetName = bom == null ? defaultEncoding : bom.getCharsetName();

            final SuppressionHandler handler = new SuppressionHandler();
            final XMLReader xmlReader = XmlUtils.buildSecureValidatingXmlReader(schemaStream14, schemaStream13, schemaStream12, schemaStream11, schemaStream10);
            xmlReader.setErrorHandler(new SuppressionErrorHandler());
            xmlReader.setContentHandler(handler);
            try (Reader reader = new InputStreamReader(bomStream, charsetName)) {
                final InputSource in = new InputSource(reader);
                xmlReader.parse(in);
                return handler.getSuppressionRules();
            }
        } catch (ParserConfigurationException | IOException ex) {
            LOGGER.debug("", ex);
            throw new SuppressionParseException(ex);
        } catch (SAXException ex) {
            if (ex.getMessage().contains("Cannot find the declaration of element 'suppressions'.")) {
                throw ex;
            } else {
                LOGGER.debug("", ex);
                throw new SuppressionParseException(ex);
            }
        }
    }

}
