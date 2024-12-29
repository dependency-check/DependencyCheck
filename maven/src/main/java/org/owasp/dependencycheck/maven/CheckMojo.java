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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import java.util.Locale;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.exception.ExceptionCollection;

/**
 * Maven Plugin that checks the project dependencies to see if they have any
 * known published vulnerabilities.
 *
 * @author Jeremy Long
 */
@Mojo(
        name = "check",
        defaultPhase = LifecyclePhase.VERIFY,
        threadSafe = true,
        requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME,
        requiresOnline = true
)
public class CheckMojo extends BaseDependencyCheckMojo {

    /**
     * The name of the report in the site.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "name", defaultValue = "dependency-check", required = true)
    private String name = "dependency-check";

    /**
     * Returns whether or not a the report can be generated.
     *
     * @return <code>true</code> if the report can be generated; otherwise
     * <code>false</code>
     */
    @Override
    public boolean canGenerateReport() {
        try {
            populateSettings();
        } catch (MojoFailureException | MojoExecutionException e) {
            return false;
        }
        boolean isCapable = false;
        for (Artifact a : getProject().getArtifacts()) {
            if (!getArtifactScopeExcluded().passes(a.getScope())) {
                isCapable = true;
                break;
            }
        }
        return isCapable;
    }

    /**
     * Returns the report name.
     *
     * @param locale the location
     * @return the report name
     */
    @Override
    public String getName(Locale locale) {
        return name;
    }

    /**
     * Gets the description of the Dependency-Check report to be displayed in
     * the Maven Generated Reports page.
     *
     * @param locale The Locale to get the description for
     * @return the description
     */
    @Override
    public String getDescription(Locale locale) {
        return "Generates a report providing details on any published vulnerabilities within project dependencies. "
                + "This report is a best effort and may contain false positives and false negatives.";
    }

    /**
     * Scans the dependencies of the project.
     *
     * @param engine the engine used to perform the scanning
     * @return a collection of exceptions
     * @throws MojoExecutionException thrown if a fatal exception occurs
     */
    @Override
    protected ExceptionCollection scanDependencies(final Engine engine) throws MojoExecutionException {
        return scanArtifacts(getProject(), engine);
    }

    /**
     * Scans the plugins of the project.
     *
     * @param engine the engine used to perform the scanning
     * @param exCollection the collection of exceptions that might have occurred
     * previously
     * @return a collection of exceptions
     * @throws MojoExecutionException thrown if a fatal exception occurs
     */
    @Override
    protected ExceptionCollection scanPlugins(final Engine engine, final ExceptionCollection exCollection) throws MojoExecutionException {
        final ExceptionCollection exCol = scanPlugins(getProject(), engine, exCollection);
        return exCol;
    }

}
