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
package org.owasp.dependencycheck.utils;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.net.URISyntaxException;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 *
 * @author Jeremy Long
 */
public abstract class BaseTest {

    /**
     * The configured settings.
     */
    private Settings settings;

    /**
     * Initialize the {@link Settings}.
     */
    @BeforeEach
    public void setUp() {
        settings = new Settings();
    }

    /**
     * Clean the {@link Settings}.
     */
    @AfterEach
    public void tearDown() {
        settings.cleanup(true);
    }

    /**
     * Returns the settings for the test cases.
     *
     * @return
     */
    protected Settings getSettings() {
        return settings;
    }

    /**
     * Returns the given resource as a File using the object's class loader. The
     * org.junit.Assume API is used so that test cases are skipped if the
     * resource is not available.
     *
     * @param o the object used to obtain a reference to the class loader
     * @param resource the name of the resource to load
     * @return the resource as an File
     */
    public static File getResourceAsFile(Object o, String resource) {
        try {
            File f = new File(o.getClass().getClassLoader().getResource(resource).toURI().getPath());
            assumeTrue(f.exists(), String.format("%n%n[SEVERE] Unable to load resource for test case: %s%n%n", resource));
            return f;
        } catch (URISyntaxException e) {
            throw new UnsupportedOperationException(e);
        }
    }
}
