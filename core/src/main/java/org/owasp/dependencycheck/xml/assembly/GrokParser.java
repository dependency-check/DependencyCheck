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
package org.owasp.dependencycheck.xml.assembly;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import javax.annotation.concurrent.ThreadSafe;
import javax.xml.parsers.ParserConfigurationException;

import org.owasp.dependencycheck.utils.AutoCloseableInputSource;
import org.owasp.dependencycheck.utils.XmlUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import static org.owasp.dependencycheck.utils.AutoCloseableInputSource.fromResource;

/**
 * A simple validating parser for XML Grok Assembly XML files.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class GrokParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(GrokParser.class);
    /**
     * The grok assembly schema file location.
     */
    public static final String GROK_SCHEMA = "schema/grok-assembly.1.0.xsd";

    /**
     * Parses the given XML file and returns the assembly data.
     *
     * @param file an XML file containing assembly data
     * @return the assembly data
     * @throws GrokParseException thrown if the XML file cannot be parsed
     */
    @SuppressFBWarnings(justification = "try with resources will clean up the input stream", value = {"OBL_UNSATISFIED_OBLIGATION"})
    public AssemblyData parse(File file) throws GrokParseException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return parse(fis);
        } catch (IOException ex) {
            LOGGER.debug("", ex);
            throw new GrokParseException(ex);
        }
    }

    /**
     * Parses the given XML stream and returns the contained assembly data.
     *
     * @param inputStream an InputStream containing assembly data
     * @return the assembly data
     * @throws GrokParseException thrown if the XML cannot be parsed
     */
    public AssemblyData parse(InputStream inputStream) throws GrokParseException {
        try (AutoCloseableInputSource schema = fromResource(GROK_SCHEMA)) {
            final GrokHandler handler = new GrokHandler();
            final XMLReader xmlReader = XmlUtils.buildSecureValidatingXmlReader(schema);
            xmlReader.setErrorHandler(new GrokErrorHandler());
            xmlReader.setContentHandler(handler);
            try (Reader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {
                final InputSource in = new InputSource(reader);
                xmlReader.parse(in);
                return handler.getAssemblyData();
            }
        } catch (ParserConfigurationException | IOException ex) {
            LOGGER.debug("", ex);
            throw new GrokParseException(ex);
        } catch (SAXException ex) {
            if (ex.getMessage().contains("Cannot find the declaration of element 'assembly'.")) {
                throw new GrokParseException("Malformed grok xml?", ex);
            } else {
                LOGGER.debug("", ex);
                throw new GrokParseException(ex);
            }
        }
    }
}
