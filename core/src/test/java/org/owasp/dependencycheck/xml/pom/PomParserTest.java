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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.pom;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import java.io.File;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 *
 * @author jeremy long
 */
class PomParserTest {

    /**
     * Test of parse method, of class PomParser.
     */
    @Test
    void testParse_File() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "pom/mailapi-1.4.3.pom");
        PomParser instance = new PomParser();
        String expVersion = "1.4.3";
        Model result = instance.parse(file);
        assertEquals(expVersion, result.getParentVersion(), "Invalid version extracted");
    }

    /**
     * Test of parse method, of class PomParser.
     */
    @Test
    void testParse_InputStream() throws Exception {
        InputStream inputStream = BaseTest.getResourceAsStream(this, "pom/plexus-utils-3.0.24.pom");
        PomParser instance = new PomParser();
        String expectedArtifactId = "plexus-utils";
        Model result = instance.parse(inputStream);
        assertEquals(expectedArtifactId, result.getArtifactId(), "Invalid artifactId extracted");
    }

    /**
     * Test of parse method, of class PomParser.
     */
    @Test
    void testParse_InputStreamWithDocType() throws Exception {
        InputStream inputStream = BaseTest.getResourceAsStream(this, "pom/mailapi-1.4.3_doctype.pom");
        PomParser instance = new PomParser();
        String expVersion = "1.4.3";
        Model result = instance.parse(inputStream);
        assertEquals(expVersion, result.getParentVersion(), "Invalid version extracted");
    }

    @Test
    void testParseWithoutDocTypeCleanup_InputStream() throws Exception {
        InputStream inputStream = BaseTest.getResourceAsStream(this, "pom/mailapi-1.4.3.pom");
        PomParser instance = new PomParser();
        String expVersion = "1.4.3";
        Model result = instance.parseWithoutDocTypeCleanup(inputStream);
        assertEquals(expVersion, result.getParentVersion(), "Invalid version extracted");
    }

    @Test
    void testParseWithoutDocTypeCleanup() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "pom/mailapi-1.4.3.pom");
        PomParser instance = new PomParser();
        String expVersion = "1.4.3";
        Model result = instance.parseWithoutDocTypeCleanup(file);
        assertEquals(expVersion, result.getParentVersion(), "Invalid version extracted");
    }


    @Test
    void testParseWithoutDocTypeCleanup_InputStreamWithDocType() {
        InputStream inputStream = BaseTest.getResourceAsStream(this, "pom/mailapi-1.4.3_doctype.pom");
        PomParser instance = new PomParser();

        assertThrows(PomParseException.class, () ->
            instance.parseWithoutDocTypeCleanup(inputStream));
    }

    @Test
    void testParseWithoutDocTypeCleanup_WithDocType() {
        File file = BaseTest.getResourceAsFile(this, "pom/mailapi-1.4.3_doctype.pom");
        PomParser instance = new PomParser();

        assertThrows(PomParseException.class, () ->
            instance.parseWithoutDocTypeCleanup(file));
    }

}
