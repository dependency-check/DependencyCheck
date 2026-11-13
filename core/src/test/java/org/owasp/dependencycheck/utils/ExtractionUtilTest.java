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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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

    /**
     * Creates a single-entry archive in the temporary directory.
     *
     * @param entryName the name of the archive entry
     * @return the path of the archive file
     * @throws IOException thrown if the archive cannot be created
     */
    private Path createArchive(final String entryName) throws IOException {
        final Path archive = tempDir.resolve("malicious.zip");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(archive))) {
            zos.putNextEntry(new ZipEntry(entryName));
            zos.write("evil".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return archive;
    }

    /**
     * Creates a destination directory named {@code dest} and a sibling
     * directory named {@code destevil}, so that containment checks based on
     * raw string prefixes would fail to detect an escape via
     * {@code ../destevil}.
     *
     * @return the path of the destination directory
     * @throws IOException thrown if the directories cannot be created
     */
    private Path createDestinationWithSibling() throws IOException {
        final Path destination = tempDir.resolve("dest");
        Files.createDirectories(destination);
        Files.createDirectories(tempDir.resolve("destevil"));
        return destination;
    }

    /**
     * A sibling directory whose name shares a string prefix with the
     * destination must not be a valid extraction target (issue #8866).
     */
    @Test
    void testExtractFilesSiblingPrefixRejected() throws Exception {
        final Path destination = createDestinationWithSibling();
        final Path archive = createArchive("../destevil/evil.txt");
        assertThrows(ExtractionException.class, () ->
            ExtractionUtil.extractFiles(archive.toFile(), destination.toFile()));
        assertFalse(Files.exists(tempDir.resolve("destevil/evil.txt")));
    }

    /**
     * Same as {@link #testExtractFilesSiblingPrefixRejected()} using the
     * engine overload.
     */
    @Test
    void testExtractFilesSiblingPrefixRejectedWithEngine() throws Exception {
        final Path destination = createDestinationWithSibling();
        final Path archive = createArchive("../destevil/evil.txt");
        assertThrows(ExtractionException.class, () ->
            ExtractionUtil.extractFiles(archive.toFile(), destination.toFile(), null));
        assertFalse(Files.exists(tempDir.resolve("destevil/evil.txt")));
    }

    /**
     * Same as {@link #testExtractFilesSiblingPrefixRejected()} using the
     * input stream overload.
     */
    @Test
    void testExtractFilesFromStreamSiblingPrefixRejected() throws Exception {
        final Path destination = createDestinationWithSibling();
        final Path archive = createArchive("../destevil/evil.txt");
        try (InputStream input = Files.newInputStream(archive)) {
            assertThrows(ExtractionException.class, () ->
                ExtractionUtil.extractFiles(input, destination.toFile()));
        }
        assertFalse(Files.exists(tempDir.resolve("destevil/evil.txt")));
    }

    /**
     * Same as {@link #testExtractFilesSiblingPrefixRejected()} using the
     * filter overload.
     */
    @Test
    void testExtractFilesUsingFilterSiblingPrefixRejected() throws Exception {
        final Path destination = createDestinationWithSibling();
        final Path archive = createArchive("../destevil/evil.txt");
        final FilenameFilter filter = new NameFileFilter("evil.txt");
        assertThrows(ExtractionException.class, () ->
            ExtractionUtil.extractFilesUsingFilter(archive.toFile(), destination.toFile(), filter));
        assertFalse(Files.exists(tempDir.resolve("destevil/evil.txt")));
    }

    /**
     * Directory entries must not escape to a sibling directory whose name
     * shares a string prefix with the destination (issue #8866).
     */
    @Test
    void testExtractFilesSiblingPrefixDirectoryRejected() throws Exception {
        final Path destination = createDestinationWithSibling();
        final Path archive = createArchive("../destevil/newdir/");
        assertThrows(ExtractionException.class, () ->
            ExtractionUtil.extractFiles(archive.toFile(), destination.toFile()));
        assertFalse(Files.exists(tempDir.resolve("destevil/newdir")));
    }

    /**
     * An existing symbolic link inside the destination that points outside
     * must not allow an entry to escape the destination.
     */
    @Test
    void testExtractFilesSymlinkEscapeRejected() throws Exception {
        final Path destination = createDestinationWithSibling();
        final Path outside = tempDir.resolve("outside");
        Files.createDirectories(outside);
        final Path link = destination.resolve("link");
        try {
            Files.createSymbolicLink(link, outside);
        } catch (IOException | UnsupportedOperationException ex) {
            Assumptions.assumeTrue(false, "symbolic links are not supported by the file system");
        }
        final Path archive = createArchive("link/escaped.txt");
        assertThrows(ExtractionException.class, () ->
            ExtractionUtil.extractFiles(archive.toFile(), destination.toFile()));
        assertFalse(Files.exists(outside.resolve("escaped.txt")));
    }

    /**
     * Same as {@link #testExtractFilesSymlinkEscapeRejected()} using the
     * filter overload.
     */
    @Test
    void testExtractFilesUsingFilterSymlinkEscapeRejected() throws Exception {
        final Path destination = createDestinationWithSibling();
        final Path outside = tempDir.resolve("outside");
        Files.createDirectories(outside);
        final Path link = destination.resolve("link");
        try {
            Files.createSymbolicLink(link, outside);
        } catch (IOException | UnsupportedOperationException ex) {
            Assumptions.assumeTrue(false, "symbolic links are not supported by the file system");
        }
        final Path archive = createArchive("link/escaped.txt");
        final FilenameFilter filter = new NameFileFilter("escaped.txt");
        assertThrows(ExtractionException.class, () ->
            ExtractionUtil.extractFilesUsingFilter(archive.toFile(), destination.toFile(), filter));
        assertFalse(Files.exists(outside.resolve("escaped.txt")));
    }

    /**
     * Archive entry names containing a NUL byte must result in an
     * ExtractionException instead of an unchecked exception.
     */
    @Test
    void testExtractFilesNulByteEntryRejected() throws Exception {
        final Path destination = createDestinationWithSibling();
        final Path archive = createArchive("../destevil/evil\u0000.txt");
        assertThrows(ExtractionException.class, () ->
            ExtractionUtil.extractFiles(archive.toFile(), destination.toFile()));
        assertFalse(Files.exists(tempDir.resolve("destevil/evil.txt")));
    }
}
