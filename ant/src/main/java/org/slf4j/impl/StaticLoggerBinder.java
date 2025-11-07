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
 * Copyright (c) 2015 The OWASP Foundation. All Rights Reserved.
 */
package org.slf4j.impl;

import org.apache.tools.ant.Task;
import org.owasp.dependencycheck.ant.logging.AntLoggerFactory;
import org.slf4j.ILoggerFactory;
import org.slf4j.spi.LoggerFactoryBinder;

/**
 * The binding of org.slf4j.LoggerFactory class with an actual instance of
 * org.slf4j.ILoggerFactory is performed using information returned by this
 * class.
 *
 * @author colezlaw
 */
//CSOFF: FinalClass
@SuppressWarnings({"squid:S1444", "squid:ClassVariableVisibilityCheck"})
public class StaticLoggerBinder implements LoggerFactoryBinder {
//CSON: FinalClass

    /**
     * The unique instance of this class
     */
    private static final StaticLoggerBinder SINGLETON = new StaticLoggerBinder();
    /**
     * Ant tasks have the log method we actually want to call. So we hang onto
     * the task as a delegate
     */
    private Task task = null;

    /**
     * Declare the version of the SLF4J API this implementation is compiled
     * against. The value of this filed is usually modified with each release.
     */
    // to avoid constant folding by the compiler, this field must *not* be final
    //CSOFF: StaticVariableName
    //CSOFF: VisibilityModifier
    @SuppressWarnings("squid:S3008")
    public static String REQUESTED_API_VERSION = "1.7.12"; // final
    //CSON: VisibilityModifier
    //CSON: StaticVariableName

    /**
     * The logger factory class string.
     */
    private static final String LOGGER_FACTORY_CLASS = AntLoggerFactory.class.getName();

    /**
     * The ILoggerFactory instance returned by the {@link #getLoggerFactory}
     * method should always be the same object
     */
    private ILoggerFactory loggerFactory;

    /**
     * Return the singleton of this class.
     *
     * @return the StaticLoggerBinder singleton
     */
    public static StaticLoggerBinder getSingleton() {
        return SINGLETON;
    }

    /**
     * Set the Task which will this is to log through.
     *
     * @param task the task through which to log
     */
    public void setTask(Task task) {
        this.task = task;
        loggerFactory = new AntLoggerFactory(task);
    }

    /**
     * Constructs a new static logger binder.
     */
    private StaticLoggerBinder() {
        loggerFactory = new AntLoggerFactory(task);
    }

    /**
     * Returns the logger factory.
     *
     * @return the logger factory
     */
    @Override
    public ILoggerFactory getLoggerFactory() {
        return loggerFactory;
    }

    /**
     * Returns the logger factory class string.
     *
     * @return the logger factory class string
     */
    @Override
    public String getLoggerFactoryClassStr() {
        return LOGGER_FACTORY_CLASS;
    }
}
