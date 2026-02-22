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
package org.owasp.dependencycheck.ant.logging;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ServiceLoader;

import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.spi.SLF4JServiceProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests that the {@link AntSlf4jServiceProvider} is discoverable via the
 * {@link ServiceLoader} mechanism and that log output is routed through the
 * Ant task.
 */
class AntSlf4jServiceProviderTest {

    @AfterEach
    void tearDown() {
        AntTaskHolder.remove();
    }

    /**
     * Verifies the META-INF/services descriptor exists in src/main/resources
     * and that ServiceLoader can discover the provider when that directory is
     * on the classpath (simulates the packaged JAR).
     */
    @Test
    void testProviderIsDiscoverableViaServiceLoader() throws Exception {
        // Build a classloader that includes src/main/resources so the
        // META-INF/services file is visible, as it would be in the packaged JAR.
        Path resources = Paths.get("src", "main", "resources");
        try (URLClassLoader cl = new URLClassLoader(
                new URL[]{resources.toUri().toURL()},
                getClass().getClassLoader())) {

            ServiceLoader<SLF4JServiceProvider> loader = ServiceLoader.load(SLF4JServiceProvider.class, cl);
            boolean found = false;
            for (SLF4JServiceProvider provider : loader) {
                if (provider instanceof AntSlf4jServiceProvider) {
                    found = true;
                    break;
                }
            }
            assertTrue(found,
                    "AntSlf4jServiceProvider was not found via ServiceLoader; "
                    + "check META-INF/services/org.slf4j.spi.SLF4JServiceProvider");
        }
    }

    /**
     * Verifies the services descriptor file contents match the provider class.
     */
    @Test
    void testServiceDescriptorContainsCorrectClassName() throws Exception {
        try (InputStream is = getClass().getClassLoader()
                .getResourceAsStream("META-INF/services/org.slf4j.spi.SLF4JServiceProvider")) {
            if (is == null) {
                // The file may not be on the test classpath due to resource
                // filtering; load it directly from source.
                Path file = Paths.get("src", "main", "resources",
                        "META-INF", "services", "org.slf4j.spi.SLF4JServiceProvider");
                assertTrue(file.toFile().exists(),
                        "Service descriptor file not found at " + file);
                try (BufferedReader reader = java.nio.file.Files.newBufferedReader(file)) {
                    String line = reader.readLine();
                    assertNotNull(line);
                    assertEquals(AntSlf4jServiceProvider.class.getName(), line.trim());
                }
            } else {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                    String line = reader.readLine();
                    assertNotNull(line);
                    assertEquals(AntSlf4jServiceProvider.class.getName(), line.trim());
                }
            }
        }
    }

    @Test
    void testInitializeCreatesFactories() {
        AntSlf4jServiceProvider provider = new AntSlf4jServiceProvider();
        provider.initialize();

        assertNotNull(provider.getLoggerFactory(), "LoggerFactory should not be null after initialize()");
        assertInstanceOf(AntLoggerFactory.class, provider.getLoggerFactory());
        assertNotNull(provider.getMarkerFactory(), "MarkerFactory should not be null after initialize()");
        assertNotNull(provider.getMDCAdapter(), "MDCAdapter should not be null after initialize()");
        assertEquals("2.0", provider.getRequestedApiVersion());
    }

    @Test
    void testLoggerFactoryReturnsAntLoggerAdapter() {
        AntSlf4jServiceProvider provider = new AntSlf4jServiceProvider();
        provider.initialize();

        Logger logger = provider.getLoggerFactory().getLogger("test.logger");
        assertInstanceOf(AntLoggerAdapter.class, logger,
                "Logger should be an AntLoggerAdapter instance");
        assertEquals("test.logger", logger.getName());
    }

    @Test
    void testLogOutputRoutedThroughAntTask() {
        Task mockTask = mock(Task.class);
        AntTaskHolder.setTask(mockTask);

        AntSlf4jServiceProvider provider = new AntSlf4jServiceProvider();
        provider.initialize();
        Logger logger = provider.getLoggerFactory().getLogger("test.routing");

        logger.info("hello from SLF4J");

        verify(mockTask).log("hello from SLF4J", Project.MSG_INFO);
    }

    @Test
    void testLogLevelMappings() {
        Task mockTask = mock(Task.class);
        AntTaskHolder.setTask(mockTask);

        AntSlf4jServiceProvider provider = new AntSlf4jServiceProvider();
        provider.initialize();
        Logger logger = provider.getLoggerFactory().getLogger("test.levels");

        logger.trace("trace-msg");
        verify(mockTask).log("trace-msg", Project.MSG_VERBOSE);

        logger.debug("debug-msg");
        verify(mockTask).log("debug-msg", Project.MSG_DEBUG);

        logger.info("info-msg");
        verify(mockTask).log("info-msg", Project.MSG_INFO);

        logger.warn("warn-msg");
        verify(mockTask).log("warn-msg", Project.MSG_WARN);

        logger.error("error-msg");
        verify(mockTask).log("error-msg", Project.MSG_ERR);
    }
}
