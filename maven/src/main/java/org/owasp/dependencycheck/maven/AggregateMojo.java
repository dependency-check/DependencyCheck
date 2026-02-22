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

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.apache.maven.model.ConfigurationContainer;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.utils.scarf.TelemetryCollector;

/**
 * Maven Plugin that checks project dependencies and the dependencies of all
 * child modules to see if they have any known published vulnerabilities.
 *
 * @author Jeremy Long
 */
@Mojo(
        name = "aggregate",
        defaultPhase = LifecyclePhase.VERIFY,
        aggregator = true,
        threadSafe = true,
        requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME,
        requiresOnline = true
)
public class AggregateMojo extends BaseDependencyCheckMojo {

    /**
     * The name of the report in the site.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "name", defaultValue = "dependency-check:aggregate", required = true)
    private String name = "dependency-check:aggregate";

    /**
     * Scans the dependencies of the projects in aggregate.
     *
     * @param engine the engine used to perform the scanning
     * @return a collection of exceptions
     * @throws MojoExecutionException thrown if a fatal exception occurs
     */
    @Override
    protected ExceptionCollection scanDependencies(final Engine engine) throws MojoExecutionException {
        TelemetryCollector.send(getSettings());
        ExceptionCollection exCol = scanArtifacts(getProject(), engine, true);
        for (MavenProject childProject : getDescendants(this.getProject())) {
            //TODO consider the following as to whether a child should be skipped per #2152
            //childProject.getBuildPlugins().get(0).getExecutions().get(0).getConfiguration()
            final ExceptionCollection ex = scanArtifacts(childProject, engine, true);
            if (ex != null) {
                if (exCol == null) {
                    exCol = ex;
                } else {
                    exCol.getExceptions().addAll(ex.getExceptions());
                }
                if (ex.isFatal()) {
                    exCol.setFatal(true);
                    final String msg = String.format("Fatal exception(s) analyzing %s", childProject.getName());
                    if (this.isFailOnError()) {
                        throw new MojoExecutionException(msg, exCol);
                    }
                    getLog().error(msg);
                    if (getLog().isDebugEnabled()) {
                        getLog().debug(exCol);
                    }
                }
            }
        }
        return exCol;
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
        ExceptionCollection exCol = scanPlugins(getProject(), engine, null);
        for (MavenProject childProject : getDescendants(this.getProject())) {
            exCol = scanPlugins(childProject, engine, exCol);
        }
        return exCol;
    }

    /**
     * Returns a set containing all the descendant projects of the given
     * project.
     *
     * @param project the project for which all descendants will be returned
     * @return the set of descendant projects
     */
    protected Set<MavenProject> getDescendants(MavenProject project) {
        if (project == null) {
            return Collections.emptySet();
        }
        final Set<MavenProject> descendants = new HashSet<>();
        int size;
        if (getLog().isDebugEnabled()) {
            getLog().debug(String.format("Collecting descendants of %s", project.getName()));
        }
        for (String m : project.getModules()) {
            for (MavenProject mod : getReactorProjects()) {
                if (!isConfiguredToSkip(mod)) {
                    try {
                        File mpp = new File(project.getBasedir(), m);
                        mpp = mpp.getCanonicalFile();
                        if (mpp.compareTo(mod.getBasedir()) == 0 && descendants.add(mod)
                                && getLog().isDebugEnabled()) {
                            getLog().debug(String.format("Descendant module %s added", mod.getName()));

                        }
                    } catch (IOException ex) {
                        if (getLog().isDebugEnabled()) {
                            getLog().debug("Unable to determine module path", ex);
                        }
                    }
                }
            }
        }
        do {
            size = descendants.size();
            for (MavenProject p : getReactorProjects()) {
                if (!isConfiguredToSkip(p)) {
                    if (project.equals(p.getParent()) || descendants.contains(p.getParent())) {
                        if (descendants.add(p) && getLog().isDebugEnabled()) {
                            getLog().debug(String.format("Descendant %s added", p.getName()));

                        }
                        for (MavenProject modTest : getReactorProjects()) {
                            if (!isConfiguredToSkip(modTest)) {
                                if (p.getModules() != null && p.getModules().contains(modTest.getName())
                                        && descendants.add(modTest)
                                        && getLog().isDebugEnabled()) {
                                    getLog().debug(String.format("Descendant %s added", modTest.getName()));
                                }
                            }
                        }
                    }
                    final Set<MavenProject> addedDescendants = new HashSet<>();
                    for (MavenProject dec : descendants) {
                        if (!isConfiguredToSkip(dec)) {
                            for (String mod : dec.getModules()) {
                                try {
                                    File mpp = new File(dec.getBasedir(), mod);
                                    mpp = mpp.getCanonicalFile();
                                    if (mpp.compareTo(p.getBasedir()) == 0) {
                                        addedDescendants.add(p);
                                    }
                                } catch (IOException ex) {
                                    if (getLog().isDebugEnabled()) {
                                        getLog().debug("Unable to determine module path", ex);
                                    }
                                }
                            }
                        }
                    }
                    for (MavenProject addedDescendant : addedDescendants) {
                        if (!isConfiguredToSkip(addedDescendant)) {
                            if (descendants.add(addedDescendant) && getLog().isDebugEnabled()) {
                                getLog().debug(String.format("Descendant module %s added", addedDescendant.getName()));
                            }
                        }
                    }
                }
            }
        } while (size != 0 && size != descendants.size());
        if (getLog().isDebugEnabled()) {
            getLog().debug(String.format("%s has %d children", project, descendants.size()));
        }
        return descendants;
    }

    /**
     * Checks the ODC configuration in the child project to see if should be
     * skipped.
     *
     * @param mavenProject the maven project to check
     * @return <code>true</code> if the project is configured to skip ODC;
     * otherwise <code>false</code>
     */
    protected boolean isConfiguredToSkip(MavenProject mavenProject) {
        final Optional<String> value = mavenProject.getBuildPlugins().stream()
                .filter(f -> "org.owasp:dependency-check-maven".equals(f.getKey()))
                .map(ConfigurationContainer::getConfiguration)
                .filter(c -> c != null && c instanceof Xpp3Dom)
                .map(c -> (Xpp3Dom) c)
                .map(c -> c.getChild("skip"))
                .filter(Objects::nonNull)
                .map(Xpp3Dom::getValue)
                .findFirst();

        final String property = mavenProject.getProperties().getProperty("dependency-check.skip");

        final boolean skip = (value.isPresent() && "true".equalsIgnoreCase(value.get())) || "true".equalsIgnoreCase(property);
        if (skip) {
            getLog().debug("Aggregation skipping " + mavenProject.getId());
        }
        return skip;
    }

    /**
     * Test if the project has pom packaging
     *
     * @param mavenProject Project to test
     * @return <code>true</code> if it has a pom packaging; otherwise
     * <code>false</code>
     */
    protected boolean isMultiModule(MavenProject mavenProject) {
        return "pom".equals(mavenProject.getPackaging());
    }

    @Override
    public boolean canGenerateReport() {
        return true; //aggregate always returns true for now - we can look at a more complicated/accurate solution later
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
        return "Generates an aggregate report of all child Maven projects providing details on any "
                + "published vulnerabilities within project dependencies. This report is a best "
                + "effort and may contain false positives and false negatives.";
    }
}
