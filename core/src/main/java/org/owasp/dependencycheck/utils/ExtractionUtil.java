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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.io.IOUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.analyzer.exception.ArchiveExtractionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Set of utilities to extract files from archives.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class ExtractionUtil {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ExtractionUtil.class);

    /**
     * Private constructor for a utility class.
     */
    private ExtractionUtil() {
    }

    /**
     * Extracts the contents of an archive into the specified directory.
     *
     * @param archive an archive file such as a WAR or EAR
     * @param extractTo a directory to extract the contents to
     * @throws ExtractionException thrown if an exception occurs while
     * extracting the files
     */
    public static void extractFiles(File archive, File extractTo) throws ExtractionException {
        extractFiles(archive, extractTo, null);
    }

    /**
     * Extracts the contents of an archive into the specified directory. The
     * files are only extracted if they are supported by the analyzers loaded
     * into the specified engine. If the engine is specified as null then all
     * files are extracted.
     *
     * @param archive an archive file such as a WAR or EAR
     * @param extractTo a directory to extract the contents to
     * @param engine the scanning engine
     * @throws ExtractionException thrown if there is an error extracting the
     * files
     */
    public static void extractFiles(File archive, File extractTo, Engine engine) throws ExtractionException {
        if (archive == null || extractTo == null) {
            return;
        }
        final Path destinationPath = getDestinationPath(extractTo);
        ZipEntry entry;
        try (FileInputStream fis = new FileInputStream(archive);
                BufferedInputStream bis = new BufferedInputStream(fis);
                ZipInputStream zis = new ZipInputStream(bis)) {
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    final File d = resolvePath(destinationPath, entry.getName()).toFile();
                    if (!d.exists() && !d.mkdirs()) {
                        final String msg = String.format("Unable to create '%s'.", d.getAbsolutePath());
                        throw new ExtractionException(msg);
                    }
                } else {
                    final File file = resolvePath(destinationPath, entry.getName()).toFile();
                    if (engine == null || engine.accept(file)) {
                        try (FileOutputStream fos = new FileOutputStream(file)) {
                            IOUtils.copy(zis, fos);
                        } catch (FileNotFoundException ex) {
                            LOGGER.debug("", ex);
                            final String msg = String.format("Unable to find file '%s'.", file.getName());
                            throw new ExtractionException(msg, ex);
                        } catch (IOException ex) {
                            LOGGER.debug("", ex);
                            final String msg = String.format("IO Exception while parsing file '%s'.", file.getName());
                            throw new ExtractionException(msg, ex);
                        }
                    }
                }
            }
        } catch (IOException ex) {
            final String msg = String.format("Exception reading archive '%s'.", archive.getName());
            LOGGER.debug("", ex);
            throw new ExtractionException(msg, ex);
        }
    }

    /**
     * Extracts the contents of an archive into the specified directory. The
     * files are only extracted if they are supported by the analyzers loaded
     * into the specified engine. If the engine is specified as null then all
     * files are extracted.
     *
     * @param archive an archive file such as a WAR or EAR
     * @param extractTo a directory to extract the contents to
     * @throws ExtractionException thrown if there is an error extracting the
     * files
     */
    public static void extractFiles(InputStream archive, File extractTo) throws ExtractionException {
        if (archive == null || extractTo == null) {
            return;
        }
        final Path destinationPath = getDestinationPath(extractTo);
        ZipEntry entry;
        try (BufferedInputStream bis = new BufferedInputStream(archive);
                ZipInputStream zis = new ZipInputStream(bis)) {
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    final File d = resolvePath(destinationPath, entry.getName()).toFile();
                    if (!d.exists() && !d.mkdirs()) {
                        final String msg = String.format("Unable to create '%s'.", d.getAbsolutePath());
                        throw new ExtractionException(msg);
                    }
                } else {
                    final File file = resolvePath(destinationPath, entry.getName()).toFile();
                    try (FileOutputStream fos = new FileOutputStream(file)) {
                        IOUtils.copy(zis, fos);
                    } catch (FileNotFoundException ex) {
                        LOGGER.debug("", ex);
                        final String msg = String.format("Unable to find file '%s'.", file.getName());
                        throw new ExtractionException(msg, ex);
                    } catch (IOException ex) {
                        LOGGER.debug("", ex);
                        final String msg = String.format("IO Exception while parsing file '%s'.", file.getName());
                        throw new ExtractionException(msg, ex);
                    }
                }
            }
        } catch (IOException ex) {
            throw new ExtractionException("Exception reading archive", ex);
        }
    }

    /**
     * Extracts the contents of an archive into the specified directory.
     *
     * @param archive an archive file such as a WAR or EAR
     * @param destination a directory to extract the contents to
     * @param filter determines which files get extracted
     * @throws ExtractionException thrown if the archive is not found
     */
    public static void extractFilesUsingFilter(File archive, File destination, FilenameFilter filter) throws ExtractionException {
        if (archive == null || destination == null) {
            return;
        }

        try (FileInputStream fis = new FileInputStream(archive)) {
            extractArchive(new ZipArchiveInputStream(new BufferedInputStream(fis)), destination, filter);
        } catch (FileNotFoundException ex) {
            final String msg = String.format("Error extracting file `%s` with filter: %s", archive.getAbsolutePath(), ex.getMessage());
            LOGGER.debug(msg, ex);
            throw new ExtractionException(msg);
        } catch (IOException | ArchiveExtractionException ex) {
            LOGGER.warn("Exception extracting archive '{}'.", archive.getAbsolutePath());
            LOGGER.debug("", ex);
            throw new ExtractionException("Unable to extract from archive", ex);
        }
    }

    /**
     * Extracts files from an archive.
     *
     * @param input the archive to extract files from
     * @param destination the location to write the files too
     * @param filter determines which files get extracted
     * @throws ArchiveExtractionException thrown if there is an exception
     * extracting files from the archive
     */
    private static void extractArchive(ArchiveInputStream input,
            File destination, FilenameFilter filter)
            throws ArchiveExtractionException {
        ArchiveEntry entry;
        try {
            final Path destinationPath = getDestinationPath(destination);

            while ((entry = input.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    final File dir = resolvePath(destinationPath, entry.getName()).toFile();
                    if (!dir.exists() && !dir.mkdirs()) {
                        final String msg = String.format(
                                "Unable to create directory '%s'.",
                                dir.getAbsolutePath());
                        throw new AnalysisException(msg);
                    }
                } else {
                    extractFile(input, destinationPath, filter, entry);
                }
            }
        } catch (IOException | AnalysisException ex) {
            throw new ArchiveExtractionException(ex);
        } finally {
            FileUtils.close(input);
        }
    }

    /**
     * Extracts a file from an archive (input stream) and correctly builds the
     * directory structure.
     *
     * @param input the archive input stream
     * @param destination where to write the file
     * @param filter the file filter to apply to the files being extracted
     * @param entry the entry from the archive to extract
     * @throws ExtractionException thrown if there is an error reading from the
     * archive stream
     */
    private static void extractFile(ArchiveInputStream input, Path destinationPath,
            FilenameFilter filter, ArchiveEntry entry) throws ExtractionException {
        final File file = resolvePath(destinationPath, entry.getName()).toFile();
        try {
            if (filter.accept(file.getParentFile(), file.getName())) {
                LOGGER.debug("Extracting '{}'", file.getPath());
                createParentFile(file);

                try (FileOutputStream fos = new FileOutputStream(file)) {
                    IOUtils.copy(input, fos);
                } catch (FileNotFoundException ex) {
                    LOGGER.debug("", ex);
                    final String msg = String.format("Unable to find file '%s'.", file.getName());
                    throw new ExtractionException(msg, ex);
                }
            }
        } catch (IOException ex) {
            LOGGER.debug("", ex);
            final String msg = String.format("IO Exception while parsing file '%s'.", file.getName());
            throw new ExtractionException(msg, ex);
        }
    }

    private static Path getDestinationPath(File destination) {
        return destination.toPath().toAbsolutePath().normalize();
    }

    private static Path resolvePath(Path destinationPath, String entryName) throws ExtractionException {
        final Path target = destinationPath.resolve(entryName).normalize();
        if (!target.startsWith(destinationPath)) {
            final String msg = String.format(
                    "Archive entry would be extracted outside of the target directory: %s",
                    entryName);
            throw new ExtractionException(msg);
        }
        return target;
    }

    /**
     * Ensures the parent path is correctly created on disk so that the file can
     * be extracted to the correct location.
     *
     * @param file the file path
     * @throws ExtractionException thrown if the parent paths could not be
     * created
     */
    private static void createParentFile(final File file) throws ExtractionException {
        final File parent = file.getParentFile();
        if (!parent.isDirectory() && !parent.mkdirs()) {
            final String msg = String.format(
                    "Unable to build directory '%s'.",
                    parent.getAbsolutePath());
            throw new ExtractionException(msg);
        }
    }

    /**
     * Extracts the file contained in a gzip archive. The extracted file is
     * placed in the exact same path as the file specified.
     *
     * @param file the archive file
     * @throws FileNotFoundException thrown if the file does not exist
     * @throws IOException thrown if there is an error extracting the file.
     */
    public static void extractGzip(File file) throws FileNotFoundException, IOException {
        final String originalPath = file.getPath();
        final File gzip = new File(originalPath + ".gz");
        if (gzip.isFile() && !gzip.delete()) {
            LOGGER.debug("Failed to delete initial temporary file when extracting 'gz' {}", gzip);
            gzip.deleteOnExit();
        }
        if (!file.renameTo(gzip)) {
            throw new IOException("Unable to rename '" + file.getPath() + "'");
        }
        final File newFile = new File(originalPath);
        try (FileInputStream fis = new FileInputStream(gzip);
                GZIPInputStream cin = new GZIPInputStream(fis);
                FileOutputStream out = new FileOutputStream(newFile)) {
            IOUtils.copy(cin, out);
        } finally {
            if (gzip.isFile() && !FileUtils.delete(gzip)) {
                LOGGER.debug("Failed to delete temporary file when extracting 'gz' {}", gzip);
                gzip.deleteOnExit();
            }
        }
    }

    /**
     * Extracts the file contained in a Zip archive. The extracted file is
     * placed in the exact same path as the file specified.
     *
     * @param file the archive file
     * @throws FileNotFoundException thrown if the file does not exist
     * @throws IOException thrown if there is an error extracting the file.
     */
    public static void extractZip(File file) throws FileNotFoundException, IOException {
        final String originalPath = file.getPath();
        final File zip = new File(originalPath + ".zip");
        if (zip.isFile() && !zip.delete()) {
            LOGGER.debug("Failed to delete initial temporary file when extracting 'zip' {}", zip);
            zip.deleteOnExit();
        }
        if (!file.renameTo(zip)) {
            throw new IOException("Unable to rename '" + file.getPath() + "'");
        }
        final File newFile = new File(originalPath);
        try (FileInputStream fis = new FileInputStream(zip);
                ZipInputStream cin = new ZipInputStream(fis);
                FileOutputStream out = new FileOutputStream(newFile)) {
            cin.getNextEntry();
            IOUtils.copy(cin, out);
        } finally {
            if (zip.isFile() && !FileUtils.delete(zip)) {
                LOGGER.debug("Failed to delete temporary file when extracting 'zip' {}", zip);
                zip.deleteOnExit();
            }
        }
    }
}
