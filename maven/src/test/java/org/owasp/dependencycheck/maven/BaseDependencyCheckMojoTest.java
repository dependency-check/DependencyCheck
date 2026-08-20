/*
 * This file is part of dependency-check-maven.
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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV2;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2Data;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.utils.CvssUtil;

import java.io.File;
import java.lang.reflect.Field;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;

/**
 *
 * @author Jeremy Long
 */
@ExtendWith(MockitoExtension.class)
class BaseDependencyCheckMojoTest extends BaseTest {

    @Spy
    MavenProject project;

    @Test
    void should_newDependency_get_pom_from_base_dir() {
        // Given
        BaseDependencyCheckMojo instance = new BaseDependencyCheckMojoImpl();

        doReturn(new File("src/test/resources/maven_project_base_dir")).when(project).getBasedir();

        String expectOutput = "pom.xml";

        // When
        String output = instance.newDependency(project).getFileName();

        // Then
        assertEquals(expectOutput, output);
    }

    @Test
    void should_newDependency_get_default_virtual_dependency() {
        // Given
        BaseDependencyCheckMojo instance = new BaseDependencyCheckMojoImpl();

        doReturn(new File("src/test/resources/dir_without_pom")).when(project).getBasedir();
        doReturn(new File("src/test/resources/dir_without_pom")).when(project).getFile();

        // When
        String output = instance.newDependency(project).getFileName();

        // Then
        assertNull(output);
    }

    @Test
    void should_newDependency_get_pom_declared_as_module() {
        // Given
        BaseDependencyCheckMojo instance = new BaseDependencyCheckMojoImpl();

        doReturn(new File("src/test/resources/dir_containing_maven_poms_declared_as_modules_in_another_pom")).when(project).getBasedir();
        doReturn(new File("src/test/resources/dir_containing_maven_poms_declared_as_modules_in_another_pom/serverlibs.pom")).when(project).getFile();

        String expectOutput = "serverlibs.pom";

        // When
        String output = instance.newDependency(project).getFileName();

        // Then
        assertEquals(expectOutput, output);
    }

    /**
     * The build is failed when <em>any</em> of the CVSS scores of a vulnerability reaches the
     * configured threshold, so the score printed in the failure message must be the score that
     * actually reached it. Reporting the score of the newest CVSS version instead quotes a score
     * below the threshold that the very same message states.
     *
     * See https://github.com/dependency-check/DependencyCheck/issues/5658
     */
    @Test
    void should_report_the_score_that_reached_the_threshold() throws Exception {
        // CVE-2021-42550 from the issue: CVSSv2 8.5 fails the build at a threshold of 7.0,
        // while CVSSv3 is only 6.6.
        final Dependency dependency = dependencyWith("CVE-2021-42550", 8.5, 6.6);

        final MojoFailureException failure = assertThrows(MojoFailureException.class,
                () -> mojoWithThreshold(7.0f).checkForFailure(new Dependency[]{dependency}));

        assertTrue(failure.getMessage().contains("CVE-2021-42550(8.5)"), failure.getMessage());
    }

    /**
     * With no threshold in play (failBuildOnCVSS &lt;= 0 reports every vulnerability) the newest
     * CVSS version is still the one to show; this guards the behaviour the change must not alter.
     */
    @Test
    void should_report_the_newest_cvss_version_without_a_threshold() throws Exception {
        final Dependency dependency = dependencyWith("CVE-2021-42550", 8.5, 6.6);

        final MojoFailureException failure = assertThrows(MojoFailureException.class,
                () -> mojoWithThreshold(0.0f).checkForFailure(new Dependency[]{dependency}));

        assertTrue(failure.getMessage().contains("CVE-2021-42550(6.6)"), failure.getMessage());
    }

    /**
     * A vulnerability whose scores all stay below the threshold is not listed at all, so the
     * build must not be failed for it.
     */
    @Test
    void should_not_fail_the_build_when_nothing_reached_the_threshold() throws Exception {
        final Dependency dependency = dependencyWith("CVE-2021-42550", 5.0, 6.6);

        assertDoesNotThrow(() -> mojoWithThreshold(9.0f).checkForFailure(new Dependency[]{dependency}));
    }

    private static Dependency dependencyWith(String cve, double cvssV2Score, double cvssV3Score) {
        final Vulnerability vulnerability = new Vulnerability(cve);
        vulnerability.setCvssV2(cvssV2WithScore(cvssV2Score));
        vulnerability.setCvssV3(CvssUtil.vectorToCvssV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", cvssV3Score));

        final Dependency dependency = new Dependency(true);
        dependency.setFileName("logback-core-1.2.3.jar");
        dependency.addVulnerability(vulnerability);
        return dependency;
    }

    /**
     * Only the base score is read by {@code checkForFailure}; the remaining metrics are left unset
     * because {@link CvssUtil#vectorToCvssV2(String, Double)} cannot round-trip a bare CVSSv2
     * vector string.
     */
    private static CvssV2 cvssV2WithScore(double baseScore) {
        final String severity = CvssUtil.cvssV2ScoreToSeverity(baseScore);
        final CvssV2Data data = new CvssV2Data(CvssV2Data.Version._2_0, null, null, null, null, null, null, null,
                baseScore, severity, null, null, null, null, null, null, null, null, null, null);
        return new CvssV2(null, null, data, severity, null, null, null, null, null, null, null);
    }

    private static BaseDependencyCheckMojo mojoWithThreshold(float threshold) throws Exception {
        final BaseDependencyCheckMojo mojo = new BaseDependencyCheckMojoImpl();
        final Field field = BaseDependencyCheckMojo.class.getDeclaredField("failBuildOnCVSS");
        field.setAccessible(true);
        field.setFloat(mojo, threshold);
        return mojo;
    }

    /**
     * Implementation of ODC Mojo for testing.
     */
    public static class BaseDependencyCheckMojoImpl extends BaseDependencyCheckMojo {

        @Override
        protected void runCheck() {
            throw new UnsupportedOperationException("Operation not supported");
        }

        @Override
        public String getName(Locale locale) {
            throw new UnsupportedOperationException("Operation not supported");
        }

        @Override
        public String getDescription(Locale locale) {
            throw new UnsupportedOperationException("Operation not supported");
        }

        @Override
        public boolean canGenerateReport() {
            throw new UnsupportedOperationException("Operation not supported");
        }

        @Override
        protected ExceptionCollection scanDependencies(Engine engine) {
            throw new UnsupportedOperationException("Operation not supported");
        }
        @Override
        protected ExceptionCollection scanPlugins(Engine engine, ExceptionCollection exCollection) {
            throw new UnsupportedOperationException("Operation not supported");
        }
    }

}
