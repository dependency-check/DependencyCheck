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

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 * @author Jeremy Long
 */
class HintHandlerTest extends BaseTest {

    @Test
    void testHandler() throws ParserConfigurationException, SAXException, IOException {
        File file = BaseTest.getResourceAsFile(this, "hints.xml");
        File schema = BaseTest.getResourceAsFile(this, "schema/dependency-hint.1.1.xsd");
        HintHandler handler = new HintHandler();

        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setValidating(true);
        SAXParser saxParser = factory.newSAXParser();
        saxParser.setProperty(HintParser.JAXP_SCHEMA_LANGUAGE, HintParser.W3C_XML_SCHEMA);
        saxParser.setProperty(HintParser.JAXP_SCHEMA_SOURCE, schema);
        XMLReader xmlReader = saxParser.getXMLReader();
        xmlReader.setErrorHandler(new HintErrorHandler());
        xmlReader.setContentHandler(handler);

        InputStream inputStream = new FileInputStream(file);
        Reader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
        InputSource in = new InputSource(reader);
        xmlReader.parse(in);

        List<HintRule> result = handler.getHintRules();
        assertEquals(2,result.size(),"two hint rules should have been loaded");
    }

}
