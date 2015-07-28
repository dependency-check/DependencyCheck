/*
 * Copyright 2014 OWASP.
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
package org.owasp.dependencycheck;

import java.io.File;
import java.io.InputStream;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long
 */
public class BaseTest {

    @BeforeClass
    public static void setUpClass() throws Exception {
        Settings.initialize();
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
        File f = new File("./target/data/dc.h2.db");
        if (f.exists() && f.isFile() && f.length() < 71680) {
            System.err.println("------------------------------------------------");
            System.err.println("------------------------------------------------");
            System.err.println("I broke the build");
            System.err.println("------------------------------------------------");
            System.err.println("------------------------------------------------");
        }

        Settings.cleanup(true);
    }

    /**
     * Returns the given resource as an InputStream using the object's class loader. The org.junit.Assume API is used so that test
     * cases are skipped if the resource is not available.
     *
     * @param o the object used to obtain a reference to the class loader
     * @param resource the name of the resource to load
     * @return the resource as an InputStream
     */
    public static InputStream getResourceAsStream(Object o, String resource) {
        getResourceAsFile(o, resource);
        return o.getClass().getClassLoader().getResourceAsStream(resource);
    }

    /**
     * Returns the given resource as a File using the object's class loader. The org.junit.Assume API is used so that test cases
     * are skipped if the resource is not available.
     *
     * @param o the object used to obtain a reference to the class loader
     * @param resource the name of the resource to load
     * @return the resource as an File
     */
    public static File getResourceAsFile(Object o, String resource) {
        File f = new File(o.getClass().getClassLoader().getResource(resource).getPath());
        Assume.assumeTrue(String.format("%n%n[SEVERE] Unable to load resource for test case: %s%n%n", resource), f.exists());
        return f;
    }
}
