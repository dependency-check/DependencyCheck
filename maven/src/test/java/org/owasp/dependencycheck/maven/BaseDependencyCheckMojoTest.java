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

import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.exception.ExceptionCollection;

import java.io.File;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
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
    void should_scoreToReport_return_the_score_that_reached_the_threshold() {
        // CVE-2021-42550 from the issue: CVSSv2 8.5 fails the build at a threshold of 7.0,
        // while CVSSv3 is only 6.6.
        assertEquals(8.5, BaseDependencyCheckMojo.scoreToReport(8.5, 6.6, -1, -1, 7.0f));
        // the newest version is used when it is the one that reached the threshold
        assertEquals(9.1, BaseDependencyCheckMojo.scoreToReport(4.0, 9.1, -1, -1, 7.0f));
        assertEquals(9.4, BaseDependencyCheckMojo.scoreToReport(4.0, 6.6, 9.4, -1, 7.0f));
        // an estimated score for an unscored severity is reported when it reached the threshold
        assertEquals(8.0, BaseDependencyCheckMojo.scoreToReport(-1, -1, -1, 8.0, 7.0f));
    }

    /**
     * With no threshold in play (failBuildOnCVSS &lt;= 0 reports every vulnerability) the newest
     * CVSS version is still the one to show; this guards the behaviour the change must not alter.
     */
    @Test
    void should_scoreToReport_prefer_the_newest_cvss_version_without_a_threshold() {
        assertEquals(6.6, BaseDependencyCheckMojo.scoreToReport(8.5, 6.6, -1, -1, 0.0f));
        assertEquals(4.0, BaseDependencyCheckMojo.scoreToReport(8.5, 6.6, 4.0, -1, 0.0f));
        assertEquals(8.5, BaseDependencyCheckMojo.scoreToReport(8.5, -1, -1, -1, 0.0f));
        // nothing scored at all - nothing to display
        assertEquals(-1.0, BaseDependencyCheckMojo.scoreToReport(-1, -1, -1, -1, 7.0f));
    }

    /**
     * A vulnerability below the threshold is never listed by checkForFailure, but the helper is
     * still expected to fall back to the newest version rather than to invent a score.
     */
    @Test
    void should_scoreToReport_fall_back_when_nothing_reached_the_threshold() {
        assertEquals(6.6, BaseDependencyCheckMojo.scoreToReport(5.0, 6.6, -1, -1, 9.0f));
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
