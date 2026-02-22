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
 * Copyright (c) 2017 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck;

import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.UnrecognizedOptionException;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.Settings.KEYS;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the {@link AppTest} class.
 */
class AppTest extends BaseTest {

    /**
     * Test of ensureCanonicalPath method, of class App.
     */
    @Test
    void testEnsureCanonicalPath() {
        String file = "../*.jar";
        App instance = new App(getSettings());
        String result = instance.ensureCanonicalPath(file);
        assertFalse(result.contains(".."));
        assertTrue(result.endsWith("*.jar"));

        file = "../some/skip/../path/file.txt";
        String expResult = "/some/path/file.txt";
        result = instance.ensureCanonicalPath(file);
        assertTrue(result.endsWith(expResult), "result=" + result);
    }

    /**
     * Assert that properties can be set on the CLI and parsed into the
     * {@link Settings}.
     *
     * @throws Exception the unexpected {@link Exception}.
     */
    @Test
    void testPopulateSettings() throws Exception {
        File prop = new File(this.getClass().getClassLoader().getResource("sample.properties").toURI().getPath());
        String[] args = {"-P", prop.getAbsolutePath()};
        Map<String, Boolean> expected = new HashMap<>();
        expected.put(Settings.KEYS.AUTO_UPDATE, Boolean.FALSE);
        expected.put(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, Boolean.TRUE);

        assertTrue(testBooleanProperties(args, expected));

        String[] args2 = {"-n"};
        expected.put(Settings.KEYS.AUTO_UPDATE, Boolean.FALSE);
        expected.put(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, Boolean.TRUE);
        assertTrue(testBooleanProperties(args2, expected));

        String[] args3 = {"-h"};
        expected.put(Settings.KEYS.AUTO_UPDATE, Boolean.TRUE);
        expected.put(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, Boolean.TRUE);
        assertTrue(testBooleanProperties(args3, expected));

        String[] args4 = {"--disableArchive"};
        expected.put(Settings.KEYS.AUTO_UPDATE, Boolean.TRUE);
        expected.put(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, Boolean.FALSE);
        assertTrue(testBooleanProperties(args4, expected));

        String[] args5 = {"-P", prop.getAbsolutePath(), "--disableArchive"};
        expected.put(Settings.KEYS.AUTO_UPDATE, Boolean.FALSE);
        expected.put(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, Boolean.FALSE);
        assertTrue(testBooleanProperties(args5, expected));

        prop = new File(this.getClass().getClassLoader().getResource("sample2.properties").toURI().getPath());
        String[] args6 = {"-P", prop.getAbsolutePath(), "--disableArchive"};
        expected.put(Settings.KEYS.AUTO_UPDATE, Boolean.TRUE);
        expected.put(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, Boolean.FALSE);
        assertTrue(testBooleanProperties(args6, expected));

        String[] args7 = {"-P", prop.getAbsolutePath(), "--noupdate"};
        expected.put(Settings.KEYS.AUTO_UPDATE, Boolean.FALSE);
        expected.put(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, Boolean.FALSE);
        assertTrue(testBooleanProperties(args7, expected));

        String[] args8 = {"-P", prop.getAbsolutePath(), "--noupdate", "--disableArchive"};
        expected.put(Settings.KEYS.AUTO_UPDATE, Boolean.FALSE);
        expected.put(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, Boolean.FALSE);
        assertTrue(testBooleanProperties(args8, expected));
    }

    /**
     * Assert that an {@link UnrecognizedOptionException} is thrown when a
     * property that is not supported is specified on the CLI.
     *
     */
    @Test
    void testPopulateSettingsException() {
        String[] args = {"-invalidPROPERTY"};
        UnrecognizedOptionException exception = assertThrows(UnrecognizedOptionException.class, () -> testBooleanProperties(args, null));
        assertTrue(exception.getMessage().contains("Unrecognized option: -invalidPROPERTY"));
    }

    /**
     * Assert that a single suppression file can be set using the CLI.
     *
     * @throws Exception the unexpected {@link Exception}.
     */
    @Test
    void testPopulatingSuppressionSettingsWithASingleFile() throws Exception {
        // GIVEN CLI properties with the mandatory arguments
        File prop = new File(this.getClass().getClassLoader().getResource("sample.properties").toURI().getPath());

        // AND a single suppression file
        String[] args = {"-P", prop.getAbsolutePath(), "--suppression", "another-file.xml"};

        // WHEN parsing the CLI arguments
        final CliParser cli = new CliParser(getSettings());
        cli.parse(args);
        final App classUnderTest = new App(getSettings());
        classUnderTest.populateSettings(cli);

        // THEN the suppression file is set in the settings for use in the application core
        String[] suppressionFiles = getSettings().getArray(KEYS.SUPPRESSION_FILE);
        assertThat("Expected the suppression file to be set in the Settings", suppressionFiles[0], is("another-file.xml"));
    }

    /**
     * Assert that multiple suppression files can be set using the CLI.
     *
     * @throws Exception the unexpected {@link Exception}.
     */
    @Test
    void testPopulatingSuppressionSettingsWithMultipleFiles() throws Exception {
        // GIVEN CLI properties with the mandatory arguments
        File prop = new File(this.getClass().getClassLoader().getResource("sample.properties").toURI().getPath());

        // AND a single suppression file
        String[] args = {"-P", prop.getAbsolutePath(), "--suppression", "first-file.xml", "--suppression", "another-file.xml"};

        // WHEN parsing the CLI arguments
        final CliParser cli = new CliParser(getSettings());
        cli.parse(args);
        final App classUnderTest = new App(getSettings());
        classUnderTest.populateSettings(cli);

        // THEN the suppression file is set in the settings for use in the application core
        assertThat("Expected the suppression files to be set in the Settings with a separator", getSettings().getString(KEYS.SUPPRESSION_FILE), is("[\"first-file.xml\",\"another-file.xml\"]"));
    }


    private boolean testBooleanProperties(String[] args, Map<String, Boolean> expected) throws FileNotFoundException, ParseException, InvalidSettingException {
        this.reloadSettings();
        final CliParser cli = new CliParser(getSettings());
        cli.parse(args);
        App instance = new App(getSettings());
        instance.populateSettings(cli);
        boolean results = true;
        for (Map.Entry<String, Boolean> entry : expected.entrySet()) {
            results &= getSettings().getBoolean(entry.getKey()) == entry.getValue();
        }
        return results;
    }
}
