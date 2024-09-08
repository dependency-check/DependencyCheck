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

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeFalse;

import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author jeremy long
 */
public class ArchiveAnalyzerTest extends BaseTest {

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        getSettings().setString(Settings.KEYS.ADDITIONAL_ZIP_EXTENSIONS, "z2, z3");
    }

    /**
     * Test of analyzeDependency method, of class ArchiveAnalyzer.
     */
    @Test
    public void testZippableExtensions() throws Exception {
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
    public void testRpmExtension() throws Exception {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize(getSettings());
        assertTrue(instance.getFileFilter().accept(new File("/srv/struts-1.2.9-162.35.1.uyuni.noarch.rpm")));
    }

}
