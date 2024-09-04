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
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import mockit.Mock;
import mockit.MockUp;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.testing.stubs.ArtifactStub;
import org.apache.maven.project.MavenProject;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.Assume;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long
 */
public class BaseDependencyCheckMojoTest extends BaseTest {

    @InjectMocks
    MavenProject project;
    
    @Test
    public void should_newDependency_get_pom_from_base_dir() {
        // Given
        BaseDependencyCheckMojo instance = new BaseDependencyCheckMojoImpl();

        new MockUp<MavenProject>() {
            @Mock
            public File getBasedir() {
                return new File("src/test/resources/maven_project_base_dir");
            }
        };

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

        new MockUp<MavenProject>() {
            @Mock
            public File getBasedir() {
                return new File("src/test/resources/dir_without_pom");
            }

            @Mock
            public File getFile() {
                return new File("src/test/resources/dir_without_pom");
            }
        };

        // When
        String output = instance.newDependency(project).getFileName();

        // Then
        assertNull(output);
    }

    @Test
    public void should_newDependency_get_pom_declared_as_module() {
        // Given
        BaseDependencyCheckMojo instance = new BaseDependencyCheckMojoImpl();

        new MockUp<MavenProject>() {
            @Mock
            public File getBasedir() {
                return new File("src/test/resources/dir_containing_maven_poms_declared_as_modules_in_another_pom");
            }

            @Mock
            public File getFile() {
                return new File("src/test/resources/dir_containing_maven_poms_declared_as_modules_in_another_pom/serverlibs.pom");
            }
        };

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
            return "test implementation";
        }

        @Override
        public String getDescription(Locale locale) {
            return "test implementation";
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
