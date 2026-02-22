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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nuget;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 *
 * @author colezlaw
 *
 */
class XPathNuspecParserTest extends BaseTest {

    /**
     * Test all the valid components.
     *
     * @throws Exception if anything goes sideways.
     */
    @Test
    void testGoodDocument() throws Exception {
        XPathNuspecParser parser = new XPathNuspecParser();
        //InputStream is = XPathNuspecParserTest.class.getClassLoader().getResourceAsStream("log4net.2.0.3.nuspec");
        InputStream is = BaseTest.getResourceAsStream(this, "log4net.2.0.3.nuspec");
        NugetPackage np = parser.parse(is);
        assertEquals("log4net", np.getId());
        assertEquals("2.0.3", np.getVersion());
        assertEquals("log4net [1.2.13]", np.getTitle());
        assertEquals("Apache Software Foundation", np.getAuthors());
        assertEquals("Apache Software Foundation", np.getOwners());
        assertEquals("http://logging.apache.org/log4net/license.html", np.getLicenseUrl());
    }

    /**
     * Expect a NuspecParseException when what we pass isn't even XML.
     *
     * @throws Exception we expect this.
     */
    @Test
    void testMissingDocument() {
        XPathNuspecParser parser = new XPathNuspecParser();
        InputStream is = BaseTest.getResourceAsStream(this, "dependencycheck.properties");
        final ByteArrayOutputStream myOut = new ByteArrayOutputStream();
        System.setErr(new PrintStream(myOut));
        assertThrows(NuspecParseException.class, () ->

            parser.parse(is));
    }

    /**
     * Expect a NuspecParseException when it's valid XML, but not a Nuspec.
     *
     * @throws Exception we expect this.
     */
    @Test
    void testNotNuspec() {
        XPathNuspecParser parser = new XPathNuspecParser();
        InputStream is = BaseTest.getResourceAsStream(this, "suppressions.xml");
        assertThrows(NuspecParseException.class, () ->
            parser.parse(is));
    }
}
