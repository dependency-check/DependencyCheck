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
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.NoDataException;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        try (URLClassLoader serviceLoader = onlyFailingUpdateSources(tempDir);
                Engine instance = new Engine(serviceLoader, getSettings())) {
            assertThrows(UpdateException.class, () -> instance.doUpdates(true));
            assertNotNull(instance.getDatabase());
        }
    }

    /**
     * Simulates an update failure with existing local data: the database has
     * already been populated (extracted by {@link BaseDBTestCase}) and the only
     * registered cached web data source fails its update. Analysis must
     * continue on the local data: {@code analyzeDependencies()} runs to
     * completion, the {@link UpdateException} is recorded as a non-fatal entry
     * in the exception collection, the post-update data check passes against
     * the existing data (no {@code NoDataException}), and the database remains
     * open until {@link Engine#close()}.
     */
    @Test
    void testAnalysisContinuesOnLocalDataAfterUpdateFailure(@TempDir Path tempDir) throws Exception {
        getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, true);
        // keep the test offline - disable analyzers that reach remote services
        getSettings().setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_PNPM_AUDIT_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_YARN_AUDIT_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_MIX_AUDIT_ENABLED, false);

        try (URLClassLoader serviceLoader = onlyFailingUpdateSources(tempDir);
                Engine instance = new Engine(serviceLoader, getSettings())) {
            instance.scanFile(BaseTest.getResourceAsFile(this, "dwr.jar"));

            final ExceptionCollection collected =
                    assertThrows(ExceptionCollection.class, instance::analyzeDependencies);

            // the update failure was recorded, but did not abort the analysis
            assertFalse(collected.isFatal());
            final UpdateException recorded =
                    assertInstanceOf(UpdateException.class, collected.getExceptions().get(0));
            assertEquals("Test update failure", recorded.getMessage());
            // the post-update data check passed on the existing data - without
            // the reopen, ensureDataExists() raises a fatal NoDataException here
            assertTrue(collected.getExceptions().stream().noneMatch(NoDataException.class::isInstance));
            assertTrue(collected.getExceptions().stream().noneMatch(DatabaseException.class::isInstance));
            // analysis ran against the existing local database
            assertNotNull(instance.getDatabase());
            assertTrue(instance.getDatabase().dataExists());
            assertTrue(instance.getDependencies().length > 0);
        }
        // reaching this point means Engine.close() completed without error
    }

    /**
     * Builds a class loader whose {@link CachedWebDataSource} service discovery
     * yields only {@link FailingCachedWebDataSource}; every other resource and
     * class lookup is delegated to the regular test class loader.
     *
     * @param tempDir directory used to host the service registration file
     * @return the class loader to construct the {@link Engine} with
     * @throws IOException if the service registration file cannot be written
     */
    private static URLClassLoader onlyFailingUpdateSources(Path tempDir) throws IOException {
        final String serviceName = "META-INF/services/" + CachedWebDataSource.class.getName();
        final Path serviceFile = tempDir.resolve(serviceName);
        Files.createDirectories(serviceFile.getParent());
        Files.writeString(serviceFile, FailingCachedWebDataSource.class.getName());
        return new URLClassLoader(new URL[]{tempDir.toUri().toURL()}, EngineTest.class.getClassLoader()) {
            @Override
            public Enumeration<URL> getResources(String name) throws IOException {
                if (serviceName.equals(name)) {
                    return findResources(name);
                }
                return super.getResources(name);
            }
        };
    }
}
