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
import org.owasp.dependencycheck.utils.AutoCloseableInputSource;
import org.owasp.dependencycheck.utils.XmlUtils;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.owasp.dependencycheck.utils.AutoCloseableInputSource.fromResource;

/**
 *
 * @author Jeremy Long
 */
class HintHandlerTest extends BaseTest {

    @Test
    void testHandler() throws ParserConfigurationException, SAXException, IOException {
        File file = BaseTest.getResourceAsFile(this, "hints.xml");
        HintHandler handler = new HintHandler();

        try (AutoCloseableInputSource schemaResource = fromResource("schema/dependency-hint.1.4.xsd")) {
            XMLReader xmlReader = XmlUtils.buildSecureValidatingXmlReader(schemaResource);
            xmlReader.setErrorHandler(new HintErrorHandler());
            xmlReader.setContentHandler(handler);

            try (Reader reader = new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8)) {
                InputSource in = new InputSource(reader);
                xmlReader.parse(in);
            }
            List<HintRule> result = handler.getHintRules();
            assertEquals(2, result.size(), "two hint rules should have been loaded");
        }
    }

}
