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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.taskdefs;

import io.github.jeremylong.jcs3.slf4j.Slf4jAdapter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.impl.StaticLoggerBinder;

/**
 * An Ant task definition to execute dependency-check during an Ant build.
 *
 * @author Jeremy Long
 */
public class Purge extends Task {

    /**
     * The properties file location.
     */
    private static final String PROPERTIES_FILE = "task.properties";
    /**
     * The configured settings.
     */
    private Settings settings;

    /**
     * The location of the data directory that contains
     */
    private String dataDirectory = null;
    /**
     * Indicates if dependency-check should fail the build if an exception
     * occurs.
     */
    private boolean failOnError = true;

    /**
     * Construct a new DependencyCheckTask.
     */
    public Purge() {
        super();

        // Call this before Dependency Check Core starts logging anything - this way, all SLF4J messages from
        // core end up coming through this tasks logger
        StaticLoggerBinder.getSingleton().setTask(this);
    }

    public Settings getSettings() {
        return settings;
    }

    /**
     * Set the value of dataDirectory.
     *
     * @param dataDirectory new value of dataDirectory
     */
    public void setDataDirectory(String dataDirectory) {
        this.dataDirectory = dataDirectory;
    }

    /**
     * Get the value of failOnError.
     *
     * @return the value of failOnError
     */
    public boolean isFailOnError() {
        return failOnError;
    }

    /**
     * Set the value of failOnError.
     *
     * @param failOnError new value of failOnError
     */
    public void setFailOnError(boolean failOnError) {
        this.failOnError = failOnError;
    }

    /**
     * Sets the
     * {@link Thread#getContextClassLoader() Thread Context Class Loader} to the
     * one for this class, and then calls
     * {@link #executeWithContextClassloader()}. This is done because the JCS
     * cache needs to have the Thread Context Class Loader set to something that
     * can resolve it's classes. Other build tools do this by default but Ant
     * does not.
     *
     * @throws BuildException throws if there is a problem. See
     * {@link #executeWithContextClassloader()} for details
     */
    @Override
    public final void execute() throws BuildException {
        muteNoisyLoggers();
        final ClassLoader current = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());

            executeWithContextClassloader();
        } finally {
            Thread.currentThread().setContextClassLoader(current);
        }
    }

    /**
     * Hacky method of muting the noisy logging from JCS.
     */
    private void muteNoisyLoggers() {
        System.setProperty("jcs.logSystem", "slf4j");
        Slf4jAdapter.muteLogging(true);

        final String[] noisyLoggers = {
            "org.apache.hc"
        };
        for (String loggerName : noisyLoggers) {
            System.setProperty("org.slf4j.simpleLogger.log." + loggerName, "error");
        }
    }

    /**
     * Executes the dependency-check purge to delete the existing local copy of
     * the NVD CVE data.
     *
     * @throws BuildException thrown if there is a problem deleting the file(s)
     */
    //see note on `Check.dealWithReferences()` for information on this suppression
    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    protected void executeWithContextClassloader() throws BuildException {
        populateSettings();
        try {
            Downloader.getInstance().configure(settings);
        } catch (InvalidSettingException e) {
            throw new BuildException(e);
        }
        try (Engine engine = new Engine(Engine.Mode.EVIDENCE_PROCESSING, getSettings())) {
            engine.purge();
        } finally {
            settings.cleanup(true);
        }
    }

    /**
     * Takes the properties supplied and updates the dependency-check settings.
     * Additionally, this sets the system properties required to change the
     * proxy server, port, and connection timeout.
     *
     * @throws BuildException thrown if the properties file cannot be read.
     */
    //see note on `Check.dealWithReferences()` for information on this suppression
    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    protected void populateSettings() throws BuildException {
        settings = new Settings();
        try (InputStream taskProperties = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE)) {
            settings.mergeProperties(taskProperties);
        } catch (IOException ex) {
            final String msg = "Unable to load the dependency-check ant task.properties file.";
            if (this.failOnError) {
                throw new BuildException(msg, ex);
            }
            log(msg, ex, Project.MSG_WARN);
        }
        if (dataDirectory != null) {
            settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDirectory);
        } else {
            final File jarPath = new File(Purge.class.getProtectionDomain().getCodeSource().getLocation().getPath());
            final File base = jarPath.getParentFile();
            final String sub = settings.getString(Settings.KEYS.DATA_DIRECTORY);
            final File dataDir = new File(base, sub);
            settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDir.getAbsolutePath());
        }
    }
}
