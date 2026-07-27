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
 * Copyright (c) 2016 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.update.CachedWebDataSource;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Jeremy Long
 */
class EngineTest extends BaseDBTestCase {


    /**
     * Test of scanFile method, of class Engine.
     *
     * @throws org.owasp.dependencycheck.data.nvdcve.DatabaseException thrown is
     * there is an exception
     */
    @Test
    void testScanFile() throws DatabaseException {
        try (Engine instance = new Engine(getSettings())) {
            instance.addFileTypeAnalyzer(new JarAnalyzer());
            File file = BaseTest.getResourceAsFile(this, "dwr.jar");
            Dependency dwr = instance.scanFile(file);
            file = BaseTest.getResourceAsFile(this, "org.mortbay.jmx.jar");
            instance.scanFile(file);
            assertEquals(2, instance.getDependencies().length);

            file = BaseTest.getResourceAsFile(this, "dwr.jar");
            Dependency secondDwr = instance.scanFile(file);

            assertEquals(2, instance.getDependencies().length);
        }
    }

    @Test
    void testDatabaseRemainsOpenAfterUpdateFailure(@TempDir Path tempDir) throws Exception {
        final String serviceName = "META-INF/services/" + CachedWebDataSource.class.getName();
        final Path serviceFile = tempDir.resolve(serviceName);
        Files.createDirectories(serviceFile.getParent());
        Files.writeString(serviceFile, FailingCachedWebDataSource.class.getName());

        try (URLClassLoader serviceLoader = new URLClassLoader(
                new URL[]{tempDir.toUri().toURL()}, getClass().getClassLoader()) {
            @Override
            public Enumeration<URL> getResources(String name) throws IOException {
                if (serviceName.equals(name)) {
                    return findResources(name);
                }
                return super.getResources(name);
            }
        };
                Engine instance = new Engine(serviceLoader, getSettings())) {
            assertThrows(UpdateException.class, () -> instance.doUpdates(true));
            assertNotNull(instance.getDatabase());
        }
    }
}
