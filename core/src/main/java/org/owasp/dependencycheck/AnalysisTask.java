/*
 * This file is part of dependency-check-core.
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
 * Copyright (c) 2016 Stefan Neuhaus. All Rights Reserved.
 */
package org.owasp.dependencycheck;

import org.owasp.dependencycheck.analyzer.Analyzer;
import org.owasp.dependencycheck.analyzer.FileTypeAnalyzer;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.Callable;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Task to support parallelism of dependency-check analysis. Analysis a single
 * {@link Dependency} by a specific {@link Analyzer}.
 *
 * @author Stefan Neuhaus
 */
@ThreadSafe
public class AnalysisTask implements Callable<Void> {

    /**
     * Instance of the logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AnalysisTask.class);

    /**
     * A reference to the analyzer.
     */
    private final Analyzer analyzer;
    /**
     * The dependency to analyze.
     */
    private final Dependency dependency;
    /**
     * A reference to the dependency-check engine.
     */
    private final Engine engine;
    /**
     * The list of exceptions that may occur during analysis.
     */
    private final List<Throwable> exceptions;

    /**
     * Creates a new analysis task.
     *
     * @param analyzer a reference of the analyzer to execute
     * @param dependency the dependency to analyze
     * @param engine the dependency-check engine
     * @param exceptions exceptions that occur during analysis will be added to
     * this collection of exceptions
     */
    public AnalysisTask(Analyzer analyzer, Dependency dependency, Engine engine, List<Throwable> exceptions) {
        this.analyzer = analyzer;
        this.dependency = dependency;
        this.engine = engine;
        this.exceptions = exceptions;
    }

    /**
     * Executes the analysis task.
     *
     * @return null
     */
    @Override
    public Void call() {
        if (shouldAnalyze()) {
            LOGGER.debug("Begin Analysis of '{}' ({})", dependency.getActualFilePath(), analyzer.getName());
            try {
                analyzer.analyze(dependency, engine);
            } catch (AnalysisException ex) {
                LOGGER.warn("An error occurred while analyzing '{}' ({}): {}", dependency.getActualFilePath(), analyzer.getName(), ex.getMessage());
                LOGGER.debug("", ex);
                exceptions.add(ex);
            } catch (Throwable ex) {
                LOGGER.warn("An unexpected error occurred during analysis of '{}' ({}): {}",
                        dependency.getActualFilePath(), analyzer.getName(), ex.getMessage());
                LOGGER.error("", ex);
                exceptions.add(ex);
            }
        }
        return null;
    }

    /**
     * Determines if the analyzer can analyze the given dependency.
     *
     * @return whether or not the analyzer can analyze the dependency
     */
    protected boolean shouldAnalyze() {
        if (analyzer instanceof FileTypeAnalyzer) {
            final FileTypeAnalyzer fileTypeAnalyzer = (FileTypeAnalyzer) analyzer;
            return fileTypeAnalyzer.accept(dependency.getActualFile());
        }
        return true;
    }
}
