/*
 * This file is part of dependency-check-utils.
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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils.processing;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.io.IOUtils;

/**
 * Utility to read the output from a `Process` and places the output into
 * provide storage containers.
 *
 * @author Jeremy Long
 */
public class ProcessReader implements AutoCloseable {

    /**
     * A reference to the process that will be read.
     */
    private final Process process;
    /**
     * Reader for the error stream.
     */
    private Gobbler errorGobbler = null;
    /**
     * Reader for the input stream.
     */
    private Gobbler inputGobbler = null;
    /**
     * Processor for the input stream.
     */
    private Processor<InputStream> processor = null;
    /**
     * A list of threads that were started.
     */
    private final List<Thread> threads = new ArrayList<>();

    /**
     * Creates a new reader for the given process. The output from the process
     * is written to the provided stores.
     *
     * @param process the process to read from
     */
    public ProcessReader(Process process) {
        this(process, null);
    }

    /**
     * Creates a new reader for the given process. The output from the process
     * is written to the provided stores.
     *
     * @param process the process to read from
     * @param processor used to process the input stream from the process
     */
    public ProcessReader(Process process, Processor<InputStream> processor) {
        this.process = process;
        this.processor = processor;
    }

    /**
     * Returns the error stream output from the process.
     *
     * @return the error stream output
     */
    public String getError() {
        return errorGobbler.getText();
    }

    /**
     * Returns the output from standard out from the process.
     *
     * @return the output from standard out from the process
     */
    public String getOutput() {
        return inputGobbler != null ? inputGobbler.getText() : null;
    }

    /**
     * Reads the standard output and standard error from the process and waits
     * for the process to complete.
     *
     * @throws InterruptedException thrown if the processing threads are
     * interrupted
     * @throws IOException thrown if there is an error reading from the process
     */
    public void readAll() throws InterruptedException, IOException {
        start();
        close();
    }

    /**
     * Starts the processing of the `process`.
     */
    private void start() {
        errorGobbler = new Gobbler(process.getErrorStream());
        startProcessor(errorGobbler);
        if (processor == null) {
            inputGobbler = new Gobbler(process.getInputStream());
            startProcessor(inputGobbler);
        } else {
            processor.setInput(process.getInputStream());
            startProcessor(processor);
        }
    }

    /**
     * Starts the process in its own thread and collects the threads so `join`
     * can be called later to ensure the thread finishes.
     *
     * @param p a reference to the processor to start.
     */
    private void startProcessor(Processor<InputStream> p) {
        if (p != null) {
            final Thread t = new Thread(p);
            threads.add(t);
            t.start();
        }
    }

    /**
     * Waits for the process and related threads to complete.
     *
     * @throws InterruptedException thrown if the processing threads are
     * interrupted
     * @throws IOException thrown if there was an error reading from the process
     */
    @Override
    public void close() throws InterruptedException, IOException {
        if (process.isAlive()) {
            process.waitFor();
        }
        if (threads.size() > 0) {
            for (Thread thread : threads) {
                thread.join();
            }
            threads.clear();
        }
        errorGobbler.close();
        if (inputGobbler != null) {
            inputGobbler.close();
        }
    }

    static class Gobbler extends Processor<InputStream> {

        /**
         * A store for an exception - if one is thrown during processing.
         */
        private IOException exception;
        /**
         * A store for the text read from the input stream.
         */
        private String text;

        Gobbler(InputStream inputStream) {
            super(inputStream);
        }

        @Override
        public void run() {
            try {
                final InputStream inputStream = getInput();
                text = IOUtils.toString(inputStream, StandardCharsets.UTF_8);

            } catch (IOException ex) {
                exception = ex;
            }
        }

        public String getText() {
            return text;
        }

        @Override
        public void close() throws IOException {
            if (exception != null) {
                throw exception;
            }
        }
    }
}
