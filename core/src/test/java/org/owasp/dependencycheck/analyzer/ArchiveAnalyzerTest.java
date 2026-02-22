/*
 * Copyright 2015 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author jeremy long
 */
class ArchiveAnalyzerTest extends BaseTest {

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        getSettings().setString(Settings.KEYS.ADDITIONAL_ZIP_EXTENSIONS, "z2, z3");
    }

    /**
     * Test of analyzeDependency method, of class ArchiveAnalyzer.
     */
    @Test
    void testZippableExtensions() {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(getSettings());
        assertTrue(instance.getFileFilter().accept(new File("c:/test.zip")));
        assertTrue(instance.getFileFilter().accept(new File("c:/test.z2")));
        assertTrue(instance.getFileFilter().accept(new File("c:/test.z3")));
        assertFalse(instance.getFileFilter().accept(new File("c:/test.z4")));
    }

    /**
     * Test of analyzeDependency method, of class ArchiveAnalyzer.
     */
    @Test
    void testRpmExtension() {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(getSettings());
        assertTrue(instance.getFileFilter().accept(new File("/srv/struts-1.2.9-162.35.1.uyuni.noarch.rpm")));
    }

}
