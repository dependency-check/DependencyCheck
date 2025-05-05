/*
 * This file is part of dependency-check-ant.
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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.taskdefs;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.BuildFileRule;
import org.apache.tools.ant.types.LogLevel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class DependencyCheckTaskIT extends BaseDBTestCase {

    private final BuildFileRule buildFileRule = new BuildFileRule();

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        final String buildFile = this.getClass().getClassLoader().getResource("build.xml").getPath();
        buildFileRule.configureProject(buildFile, LogLevel.VERBOSE.getLevel());
    }

    @AfterEach
    @Override
    public void tearDown() throws Exception {
        if (buildFileRule.getProject() != null) {
            if (this.buildFileRule.getProject().getTargets().containsKey("tearDown")) {
                this.buildFileRule.getProject().executeTarget("tearDown");
            }
        }
        super.tearDown();
    }

    /**
     * Test of addFileSet method, of class DependencyCheckTask.
     */
    @Test
    void testAddFileSet() throws Exception {
        File report = new File("target/dependency-check-report.html");
        if (report.exists() && !report.delete()) {
            throw new Exception("Unable to delete 'target/dependency-check-report.html' prior to test.");
        }
        buildFileRule.executeTarget("test.fileset");
        assertTrue(report.exists(), "DependencyCheck report was not generated");
    }

    /**
     * Test of addFileList method, of class DependencyCheckTask.
     *
     * @throws Exception
     */
    @Test
    void testAddFileList() throws Exception {
        File report = new File("target/dependency-check-report.xml");
        if (report.exists()) {
            if (!report.delete()) {
                throw new Exception("Unable to delete 'target/DependencyCheck-Report.xml' prior to test.");
            }
        }
        buildFileRule.executeTarget("test.filelist");

        assertTrue(report.exists(), "DependencyCheck report was not generated");
    }

    /**
     * Test of addDirSet method, of class DependencyCheckTask.
     *
     * @throws Exception
     */
    @Test
    void testAddDirSet() throws Exception {
        File report = new File("target/dependency-check-report.csv");
        if (report.exists()) {
            if (!report.delete()) {
                throw new Exception("Unable to delete 'target/DependencyCheck-Vulnerability.html' prior to test.");
            }
        }
        buildFileRule.executeTarget("test.dirset");
        assertTrue(report.exists(), "DependencyCheck report was not generated");
    }

    @Test
    void testNestedReportFormat() throws Exception {
        File reportHTML = new File("target/dependency-check-report.html");
        File reportCSV = new File("target/dependency-check-report.csv");
        if (reportCSV.exists()) {
            if (!reportCSV.delete()) {
                throw new Exception("Unable to delete 'target/DependencyCheck-Vulnerability.html' prior to test.");
            }
        }
        if (reportHTML.exists()) {
            if (!reportHTML.delete()) {
                throw new Exception("Unable to delete 'target/DependencyCheck-Vulnerability.csv' prior to test.");
            }
        }
        buildFileRule.executeTarget("test.formatNested");
        assertTrue(reportCSV.exists(), "DependencyCheck CSV report was not generated");
        assertTrue(reportHTML.exists(), "DependencyCheck HTML report was not generated");
    }

    @Test
    void testNestedBADReportFormat() {
        BuildException e = assertThrows(BuildException.class,
                () -> buildFileRule.executeTarget("test.formatBADNested"),
                "Should have had a buildException for a bad format attribute");
        assertTrue(e.getMessage().contains("BAD is not a legal value for this attribute"),
                "Message did not have BAD, unexpected exception: " + e.getMessage());
    }

    /**
     * Test of getFailBuildOnCVSS method, of class DependencyCheckTask.
     */
    @Test
    void testGetFailBuildOnCVSS() {
        Exception exception = assertThrows(BuildException.class, () -> buildFileRule.executeTarget("failCVSS"));

        String expectedMessage = String.format("One or more dependencies were identified with vulnerabilities that "
                + "have a CVSS score greater than or equal to '%.1f':", 3.0f);

        assertTrue(exception.getMessage().contains(expectedMessage));
    }

    /**
     * Test the DependencyCheckTask where a CVE is suppressed.
     */
    @Test
    void testSuppressingCVE() {
        // GIVEN an ant task with a vulnerability
        final String antTaskName = "suppression";

        // WHEN executing the ant task
        buildFileRule.executeTarget(antTaskName);
        if (buildFileRule.getError() != null && !buildFileRule.getError().isEmpty()) {
            System.out.println("----------------------------------------------------------");
            System.out.println(buildFileRule.getError());
            System.out.println("----------------------------------------------------------");
            System.out.println(buildFileRule.getFullLog());
            System.out.println("----------------------------------------------------------");
        }

        // THEN the ant task executed without error
        final File report = new File("target/suppression-report.html");
        assertTrue(report.exists(), "Expected the DependencyCheck report to be generated");
    }

    /**
     * Test the DependencyCheckTask deprecated suppression property throws an
     * exception with a warning.
     */
    @Test
    void testSuppressingSingle() {
        // GIVEN an ant task with a vulnerability using the legacy property
        final String antTaskName = "suppression-single";
        // WHEN executing the ant task
        buildFileRule.executeTarget(antTaskName);

        // THEN the ant task executed without error
        final File report = new File("target/suppression-single-report.html");
        assertTrue(report.exists(), "Expected the DependencyCheck report to be generated");
    }

    /**
     * Test the DependencyCheckTask deprecated suppression property throws an
     * exception with a warning.
     */
    @Test
    void testSuppressingMultiple() {
        // GIVEN an ant task with a vulnerability using multiple was to configure the suppression file
        final String antTaskName = "suppression-multiple";
        // WHEN executing the ant task
        buildFileRule.executeTarget(antTaskName);

        // THEN the ant task executed without error
        final File report = new File("target/suppression-multiple-report.html");
        assertTrue(report.exists(), "Expected the DependencyCheck report to be generated");
    }

    /**
     * Test the DependencyCheckTask retireJS configuration.
     */
    @Test
    void testRetireJsConfiguration() {
        // GIVEN an ant task with a vulnerability using multiple was to configure the suppression file
        final String antTaskName = "retireJS";

        // WHEN executing the ant task
        buildFileRule.executeTarget(antTaskName);

        // THEN the ant task executed without error
        final File report = new File("target/retirejs-report.html");
        assertTrue(report.exists(), "Expected the DependencyCheck report to be generated");
    }
}
