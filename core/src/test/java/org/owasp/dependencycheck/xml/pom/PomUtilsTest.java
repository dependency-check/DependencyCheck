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
 * Copyright (c) 2015 The OWASP Foundatio. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.pom;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;

import java.io.File;
import java.util.jar.JarFile;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test the PomUtils object.
 *
 * @author Jeremy Long
 */
class PomUtilsTest extends BaseTest {

    /**
     * Test of readPom method, of class PomUtils.
     *
     * @throws java.lang.Exception thrown when the test fails due to an
     * exception
     */
    @Test
    void testReadPom_File() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "dwr-pom.xml");
        String expResult = "Direct Web Remoting";
        Model result = PomUtils.readPom(file);
        assertEquals(expResult, result.getName());

        expResult = "get ahead";
        assertEquals(expResult, result.getOrganization());
        expResult = "http://getahead.ltd.uk/dwr";
        assertEquals(expResult, result.getOrganizationUrl());

        file = BaseTest.getResourceAsFile(this, "jmockit-1.26.pom");
        expResult = "Main ø modified to test issue #710 and #801 (&amps;)";
        result = PomUtils.readPom(file);
        assertEquals(expResult, result.getName());

        file = BaseTest.getResourceAsFile(this, "pom/mailapi-1.4.3_projectcomment.pom");
        expResult = "JavaMail API jar";
        result = PomUtils.readPom(file);
        assertEquals(expResult, result.getName());
    }

    @Test
    void testReadPom_String_File() throws Exception {
        File fileCommonValidator = BaseTest.getResourceAsFile(this, "commons-validator-1.4.0.jar");
        JarFile jar = new JarFile(fileCommonValidator, false);
        String expResult = "Commons Validator";
        Model result = PomUtils.readPom("META-INF/maven/commons-validator/commons-validator/pom.xml", jar);
        assertEquals(expResult, result.getName());
    }

    @Test
    void testReadPom_should_trim_version() throws AnalysisException {
        File input = BaseTest.getResourceAsFile(this, "pom/pom-with-new-line.xml");
        String expectedOutputVersion = "2.2.0";

        Model output = PomUtils.readPom(input);

        assertEquals(expectedOutputVersion, output.getVersion());
    }

}
