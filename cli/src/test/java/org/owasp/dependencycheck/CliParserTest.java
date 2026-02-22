/*
 * This file is part of Dependency-Check.
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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck;

import org.apache.commons.cli.ParseException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 *
 * @author Jeremy Long
 */
class CliParserTest extends BaseTest {

    /**
     * Test of parse method, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    void testParse() throws Exception {

        String[] args = {};

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));

        CliParser instance = new CliParser(getSettings());
        instance.parse(args);

        assertFalse(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with help arg, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    void testParse_help() throws Exception {

        String[] args = {"-help"};

        CliParser instance = new CliParser(getSettings());
        instance.parse(args);

        assertFalse(instance.isGetVersion());
        assertTrue(instance.isGetHelp());
        assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with version arg, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    void testParse_version() throws Exception {

        String[] args = {"-version"};

        CliParser instance = new CliParser(getSettings());
        instance.parse(args);
        assertTrue(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertFalse(instance.isRunScan());

    }

    /**
     * Test of parse method with failOnCVSS without an argument
     *
     */
    @Test
    void testParse_failOnCVSSNoArg() {

        String[] args = {"--failOnCVSS"};

        CliParser instance = new CliParser(getSettings());
        ParseException ex = assertThrows(ParseException.class, () -> instance.parse(args),
                "an argument for failOnCVSS was missing and an exception was not thrown");
        assertTrue(ex.getMessage().contains("Missing argument"));

        assertFalse(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with failOnCVSS invalid argument. It should default
     * to 11
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    void testParse_failOnCVSSInvalidArgument() throws Exception {

        String[] args = {"--failOnCVSS", "bad"};

        CliParser instance = new CliParser(getSettings());
        instance.parse(args);
        assertEquals(11.0, instance.getFailOnCVSS(), 0, "Default should be 11");
        assertFalse(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with failOnCVSS invalid argument. It should default
     * to 11
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    void testParse_failOnCVSSValidArgument() throws Exception {

        String[] args = {"--failOnCVSS", "6"};

        CliParser instance = new CliParser(getSettings());
        instance.parse(args);
        assertEquals(6.0, instance.getFailOnCVSS(), 0);
        assertFalse(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with jar and cpe args, of class CliParser.
     *
     */
    @Test
    void testParse_unknown() {

        String[] args = {"-unknown"};

        ByteArrayOutputStream baos_out = new ByteArrayOutputStream();
        ByteArrayOutputStream baos_err = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos_out));
        System.setErr(new PrintStream(baos_err));

        CliParser instance = new CliParser(getSettings());

        ParseException ex = assertThrows(ParseException.class, () -> instance.parse(args) ,
                "Unrecognized option should have caused an exception");
        assertTrue(ex.getMessage().contains("Unrecognized option"));

        assertFalse(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with scan arg, of class CliParser.
     *
     */
    @Test
    void testParse_scan() {

        String[] args = {"-scan"};

        CliParser instance = new CliParser(getSettings());

        ParseException ex = assertThrows(ParseException.class, () -> instance.parse(args),
                "Missing argument should have caused an exception");
        assertTrue(ex.getMessage().contains("Missing argument"));

        assertFalse(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with jar arg, of class CliParser.
     *
     */
    @Test
    void testParse_scan_unknownFile() {

        String[] args = {"-scan", "jar.that.does.not.exist", "--project", "test"};

        CliParser instance = new CliParser(getSettings());

        FileNotFoundException ex = assertThrows(FileNotFoundException.class, () -> instance.parse(args),
                "An exception should have been thrown");
        assertTrue(ex.getMessage().contains("Invalid 'scan' argument"));

        assertFalse(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with jar arg, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    void testParse_scan_withFileExists() throws Exception {
        File path = new File(this.getClass().getClassLoader().getResource("checkSumTest.file").toURI().getPath());
        String[] args = {"--scan", path.getCanonicalPath(), "--out", "./", "--project", "test"};

        CliParser instance = new CliParser(getSettings());
        instance.parse(args);

        assertEquals(path.getCanonicalPath(), instance.getScanFiles()[0]);

        assertFalse(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertTrue(instance.isRunScan());
    }

    /**
     * Test of printVersionInfo, of class CliParser.
     *
     */
    @Test
    @SuppressWarnings("StringSplitter")
    void testParse_printVersionInfo() {

        PrintStream out = System.out;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));

        CliParser instance = new CliParser(getSettings());
        instance.printVersionInfo();
        try {
            baos.flush();
            String text = baos.toString(UTF_8).toLowerCase();
            String[] lines = text.split(System.lineSeparator());
            assertTrue(lines.length >= 1);
            assertTrue(text.contains("version"));
            assertFalse(text.contains("unknown"));
        } catch (IOException ex) {
            System.setOut(out);
            fail("CliParser.printVersionInfo did not write anything to system.out.", ex);
        } finally {
            System.setOut(out);
        }
    }

    /**
     * Test of printHelp, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    @SuppressWarnings("StringSplitter")
    void testParse_printHelp() throws Exception {

        PrintStream out = System.out;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));

        CliParser instance = new CliParser(getSettings());
        String[] args = {"-h"};
        instance.parse(args);
        instance.printHelp();
        args[0] = "--advancedHelp";
        instance.parse(args);
        instance.printHelp();
        try {
            baos.flush();
            String text = (baos.toString(UTF_8));
            String[] lines = text.split(System.lineSeparator());
            assertTrue(lines[0].startsWith("usage: "));
            assertTrue((lines.length > 2));
        } catch (IOException ex) {
            System.setOut(out);
            fail("CliParser.printVersionInfo did not write anything to system.out.");
        } finally {
            System.setOut(out);
        }
    }

    /**
     * Test of getBooleanArgument method, of class CliParser.
     */
    @Test
    void testGetBooleanArgument() {
        String[] args = {"--scan", "missing.file", "--artifactoryUseProxy", "false", "--artifactoryParallelAnalysis", "true", "--project", "test"};

        CliParser instance = new CliParser(getSettings());

        FileNotFoundException ex = assertThrows(FileNotFoundException.class, () -> instance.parse(args),
                "invalid scan should have caused an error");
        assertTrue(ex.getMessage().contains("Invalid 'scan' argument"));

        boolean expResult;
        Boolean result = instance.getBooleanArgument("missingArgument");
        assertNull(result);

        expResult = false;
        result = instance.getBooleanArgument(CliParser.ARGUMENT.ARTIFACTORY_USES_PROXY);
        assertEquals(expResult, result);
        expResult = true;
        result = instance.getBooleanArgument(CliParser.ARGUMENT.ARTIFACTORY_PARALLEL_ANALYSIS);
        assertEquals(expResult, result);
    }

    /**
     * Test of getStringArgument method, of class CliParser.
     */
    @Test
    void testGetStringArgument() {

        String[] args = {"--scan", "missing.file", "--artifactoryUsername", "blue42", "--project", "test"};

        CliParser instance = new CliParser(getSettings());

        FileNotFoundException ex = assertThrows(FileNotFoundException.class, () -> instance.parse(args),
                "invalid scan argument should have caused an exception");
        assertTrue(ex.getMessage().contains("Invalid 'scan' argument"));

        String expResult;
        String result = instance.getStringArgument("missingArgument");
        assertNull(result);

        expResult = "blue42";
        result = instance.getStringArgument(CliParser.ARGUMENT.ARTIFACTORY_USERNAME);
        assertEquals(expResult, result);
    }

    @Test
    void testHasOption() {

        String[] args = {"--scan", "missing.file", "--artifactoryUsername", "blue42", "--project", "test"};

        CliParser instance = new CliParser(getSettings());

        FileNotFoundException ex = assertThrows(FileNotFoundException.class, () -> instance.parse(args),
                "invalid scan argument should have caused an exception");
        assertTrue(ex.getMessage().contains("Invalid 'scan' argument"));

        Boolean result = instance.hasOption("missingOption");
        assertNull(result);

        Boolean expResult = true;
        result = instance.hasOption(CliParser.ARGUMENT.PROJECT);
        assertEquals(expResult, result);
    }
}
