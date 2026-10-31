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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.apache.commons.io.filefilter.NameFileFilter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;

import java.io.File;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 *
 * @author Jeremy Long
 */
class ExtractionUtilTest extends BaseTest {

    /**
     * Test of extractFiles method, of class ExtractionUtil.
     */
    @Test
    void testExtractFiles_File_File() throws Exception {
        File destination = getSettings().getTempDirectory();
        File archive = BaseTest.getResourceAsFile(this, "evil.zip");
        assertThrows(org.owasp.dependencycheck.utils.ExtractionException.class, () ->
            ExtractionUtil.extractFiles(archive, destination));
    }

    /**
     * Test of extractFiles method, of class ExtractionUtil.
     */
    @Test
    void testExtractFiles_3args() throws Exception {
        File destination = getSettings().getTempDirectory();
        File archive = BaseTest.getResourceAsFile(this, "evil.zip");
        Engine engine = null;
        assertThrows(org.owasp.dependencycheck.utils.ExtractionException.class, () ->
            ExtractionUtil.extractFiles(archive, destination, engine));
    }

    /**
     * Test of extractFilesUsingFilter method, of class ExtractionUtil.
     */
    @Test
    void testExtractFilesUsingFilter() throws Exception {
        File destination = getSettings().getTempDirectory();
        File archive = BaseTest.getResourceAsFile(this, "evil.zip");
        assertThrows(org.owasp.dependencycheck.utils.ExtractionException.class, () ->
            ExtractionUtil.extractFiles(archive, destination));
        FilenameFilter filter = new NameFileFilter("evil.txt");
        assertThrows(org.owasp.dependencycheck.utils.ExtractionException.class, () ->
            ExtractionUtil.extractFilesUsingFilter(archive, destination, filter));
    }

    @TempDir
    Path tempDir;

    private Path createArchive(String entryName, String content) throws Exception {
        Path archive = tempDir.resolve("malicious-" + System.nanoTime() + ".zip");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(archive))) {
            zos.putNextEntry(new ZipEntry(entryName));
            zos.write(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return archive;
    }

    private Path createDestination() throws Exception {
        Path destination = tempDir.resolve("dest");
        Files.createDirectories(destination);
        Files.createDirectories(tempDir.resolve("destevil"));
        return destination;
    }

    @Test
    void testSiblingPrefixFileRejected() throws Exception {
        Path destination = createDestination();
        Path archive = createArchive("../destevil/evil.txt", "evil");
        assertThrows(ExtractionException.class, () ->
                ExtractionUtil.extractFiles(archive.toFile(), destination.toFile()));
        assertFalse(Files.exists(tempDir.resolve("destevil/evil.txt")));
    }

    @Test
    void testSiblingPrefixFileRejectedWithEngine() throws Exception {
        Path destination = createDestination();
        Path archive = createArchive("../destevil/evil.txt", "evil");
        assertThrows(ExtractionException.class, () ->
                ExtractionUtil.extractFiles(archive.toFile(), destination.toFile(), null));
        assertFalse(Files.exists(tempDir.resolve("destevil/evil.txt")));
    }

    @Test
    void testSiblingPrefixFileRejectedFromStream() throws Exception {
        Path destination = createDestination();
        Path archive = createArchive("../destevil/evil.txt", "evil");
        try (InputStream input = Files.newInputStream(archive)) {
            assertThrows(ExtractionException.class, () ->
                    ExtractionUtil.extractFiles(input, destination.toFile()));
        }
        assertFalse(Files.exists(tempDir.resolve("destevil/evil.txt")));
    }

    @Test
    void testSiblingPrefixFileRejectedUsingFilter() throws Exception {
        Path destination = createDestination();
        Path archive = createArchive("../destevil/evil.txt", "evil");
        FilenameFilter filter = (dir, name) -> name.equals("evil.txt");
        assertThrows(ExtractionException.class, () ->
                ExtractionUtil.extractFilesUsingFilter(archive.toFile(), destination.toFile(), filter));
        assertFalse(Files.exists(tempDir.resolve("destevil/evil.txt")));
    }

    @Test
    void testSiblingPrefixDirectoryRejected() throws Exception {
        Path destination = createDestination();
        Path archive = createArchive("../destevil/newdir/", "");
        assertThrows(ExtractionException.class, () ->
                ExtractionUtil.extractFiles(archive.toFile(), destination.toFile()));
        assertFalse(Files.exists(tempDir.resolve("destevil/newdir")));
    }
}
