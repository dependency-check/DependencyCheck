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
import java.io.PrintStream;
import java.io.StringWriter;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

        CliParser instance = new CliParser(getSettings());
        instance.parse();

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

        CliParser instance = new CliParser(getSettings());

        ParseException ex = assertThrows(ParseException.class, () -> instance.parse("-unknown"),
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
    void testParse_printVersionInfo() {

        PrintStream out = System.out;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos, true, UTF_8));

        CliParser instance = new CliParser(getSettings());
        instance.printVersionInfo();
        try {
            assertThat(baos.toString(UTF_8), matchesPattern("(?mi)dependency-check.*version [0-9]+.*\n"));
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
    void testParse_printHelp() throws Exception {
        CliParser instance = new CliParser(getSettings());
        instance.parse("-h");
        StringWriter text = new StringWriter();
        instance.printHelp(text);

        List<String> lines = text.toString().lines().collect(toList());
        assertThat(lines, containsInRelativeOrder(startsWith(" usage:  dependency-check"), startsWith(" -v, --version")));
        assertThat(lines.size(), greaterThan(10));
    }

    /**
     * Test of printHelp, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    void testParse_printHelpAdvanced() throws Exception {
        CliParser instance = new CliParser(getSettings());
        instance.parse("--advancedHelp");
        StringWriter text = new StringWriter();
        instance.printHelp(text);

        List<String> lines = text.toString().lines().collect(toList());
        assertThat(lines, containsInRelativeOrder(startsWith(" usage:  dependency-check"), startsWith(" -c, --connectiontimeout"), startsWith(" -v, --version")));
        assertThat(lines.size(), greaterThan(60));
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
