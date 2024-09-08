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

import java.io.File;
import java.util.Locale;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.doReturn;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.exception.ExceptionCollection;

/**
 *
 * @author Jeremy Long
 */
@RunWith(MockitoJUnitRunner.class)
public class BaseDependencyCheckMojoTest extends BaseTest {

    @Spy
    MavenProject project;

    @Test
    public void should_newDependency_get_pom_from_base_dir() {
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
    public void should_newDependency_get_default_virtual_dependency() {
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
    public void should_newDependency_get_pom_declared_as_module() {
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
     * Implementation of ODC Mojo for testing.
     */
    public static class BaseDependencyCheckMojoImpl extends BaseDependencyCheckMojo {

        @Override
        protected void runCheck() throws MojoExecutionException, MojoFailureException {
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
        protected ExceptionCollection scanDependencies(Engine engine) throws MojoExecutionException {
            throw new UnsupportedOperationException("Operation not supported");
        }
        @Override
        protected ExceptionCollection scanPlugins(Engine engine, ExceptionCollection exCollection) throws MojoExecutionException {
            throw new UnsupportedOperationException("Operation not supported");
        }
    }

}
