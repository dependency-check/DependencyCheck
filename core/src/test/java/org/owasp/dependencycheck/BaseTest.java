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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

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
    public void setUp() throws Exception {
        settings = new Settings();
    }

    /**
     * Clean the {@link Settings}.
     */
    @AfterEach
    public void tearDown() throws Exception {
        settings.cleanup(true);
    }

    @AfterAll
    public static void tearDownClass() {
        File f = new File("./target/data/odc.mv.db");
        if (f.exists() && f.isFile() && f.length() < 71680) {
            System.err.println("------------------------------------------------");
            System.err.println("------------------------------------------------");
            System.err.println("Test referenced CveDB() and does not extend BaseDbTestCases?");
            System.err.println("------------------------------------------------");
            System.err.println("------------------------------------------------");
        }
    }

    /**
     * Returns the given resource as an InputStream using the object's class loader.
     *
     * @param o        the object used to obtain a reference to the class loader
     * @param resource the name of the resource to load
     * @return the resource as an InputStream
     */
    public static @NonNull InputStream getResourceAsStream(Object o, String resource) {
        return Objects.requireNonNull(o.getClass().getClassLoader().getResourceAsStream(resource), resource + " not found on classpath");
    }

    /**
     * Returns the given resource as a File using the object's class loader.
     *
     * @param o        the object used to obtain a reference to the class loader
     * @param resource the name of the resource to load
     * @return the resource as a File
     */
    public static @NonNull File getResourceAsFile(Object o, String resource) {
        return new File(getResourceAsURI(o, resource).getPath());
    }

    /**
     * Returns the given resource as a URI using the object's class loader.
     *
     * @param o        the object used to obtain a reference to the class loader
     * @param resource the name of the resource to load
     * @return the resource as a URI
     */
    public static @NonNull URI getResourceAsURI(Object o, String resource) {
        try {
            return Objects.requireNonNull(o.getClass().getClassLoader().getResource(resource), resource + " not found on classpath").toURI();
        } catch (URISyntaxException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    /**
     * Returns the given resource as a URL string using the object's class loader.
     *
     * @param o        the object used to obtain a reference to the class loader
     * @param resource the name of the resource to load
     * @return the resource as a URL string
     */
    public static @NonNull String getResourceAsUrlString(Object o, String resource) {
        try {
            return getResourceAsURI(o, resource).toURL().toString();
        } catch (MalformedURLException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    /**
     * Returns the given resource content using the object's class loader.
     *
     * @param o        the object used to obtain a reference to the class loader
     * @param resource the name of the resource to load
     * @return the resource as a String
     */
    public static @NonNull String getResourceAsContentString(Object o, String resource) {
        try (InputStream is = getResourceAsStream(o, resource)) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    /**
     * @return the settings for the test cases.
     */
    protected Settings getSettings() {
        return settings;
    }
}
