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
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Maven Plugin that updates the local cache of the NVD data from NIST.
 *
 * @author Jeremy Long
 */
@Mojo(
        name = "update-only",
        requiresProject = false,
        defaultPhase = LifecyclePhase.GENERATE_RESOURCES,
        threadSafe = true,
        requiresDependencyResolution = ResolutionScope.NONE,
        requiresOnline = true,
        aggregator = true
)
public class UpdateMojo extends BaseDependencyCheckMojo {

    /**
     * Returns false; this mojo cannot generate a report.
     *
     * @return <code>false</code>
     */
    @Override
    public boolean canGenerateReport() {
        return false;
    }

    /**
     * Executes the dependency-check engine on the project's dependencies and
     * generates the report.
     *
     * @throws MojoExecutionException thrown if there is an exception executing
     * the goal
     * @throws MojoFailureException thrown if dependency-check is configured to
     * fail the build
     */
    @Override
    protected void runCheck() throws MojoExecutionException, MojoFailureException {
        muteNoisyLoggers();
        try (Engine engine = initializeEngine()) {
            try {
                if (!engine.getSettings().getBoolean(Settings.KEYS.AUTO_UPDATE)) {
                    engine.getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
                }
            } catch (InvalidSettingException ex) {
                engine.getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            }
            engine.doUpdates();
        } catch (DatabaseException ex) {
            if (getLog().isDebugEnabled()) {
                getLog().debug("Database connection error", ex);
            }
            final String msg = "An exception occurred connecting to the local database. Please see the log file for more details.";
            if (this.isFailOnError()) {
                throw new MojoExecutionException(msg, ex);
            }
            getLog().error(msg);
        } catch (UpdateException ex) {
            final String msg = "An exception occurred while downloading updates. Please see the log file for more details.";
            if (this.isFailOnError()) {
                throw new MojoExecutionException(msg, ex);
            }
            getLog().error(msg);
        } finally {
            getSettings().cleanup();
        }
    }

    /**
     * Returns the report name.
     *
     * @param locale the location
     * @return the report name
     */
    @Override
    public String getName(Locale locale) {
        return "dependency-check-update";
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
        return "Updates the local cache of the NVD data from NIST.";
    }

    /**
     * Throws an exception if called. The update mojo does not scan
     * dependencies.
     *
     * @param engine the engine used to scan
     * @return a collection of exceptions
     * @throws MojoExecutionException thrown if there is an exception
     */
    @Override
    protected ExceptionCollection scanDependencies(Engine engine) throws MojoExecutionException {
        throw new UnsupportedOperationException("Operation not supported");
    }

    /**
     * Throws an exception if called. The purge mojo does not scan dependencies.
     *
     * @param engine the engine used to scan
     * @param exCollection the collection of exceptions that might have occurred
     * previously
     * @return a collection of exceptions
     * @throws MojoExecutionException thrown if there is an exception
     */
    @Override
    protected ExceptionCollection scanPlugins(final Engine engine, final ExceptionCollection exCollection) throws MojoExecutionException {
        throw new UnsupportedOperationException("Operation not supported");
    }
}
