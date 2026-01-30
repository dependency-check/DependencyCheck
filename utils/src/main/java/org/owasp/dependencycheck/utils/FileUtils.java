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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.UUID;
import java.util.stream.Stream;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.SystemUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A collection of utilities for processing information about files.
 *
 * @author Jeremy Long
 */
public final class FileUtils {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(FileUtils.class);
    /**
     * Bit bucket for non-Windows systems
     */
    private static final String BIT_BUCKET_UNIX = "/dev/null";

    /**
     * Bit bucket for Windows systems (yes, only one 'L')
     */
    private static final String BIT_BUCKET_WIN = "NUL";

    /**
     * Private constructor for a utility class.
     */
    private FileUtils() {
    }

    /**
     * Returns the (lowercase) file extension for a specified file.
     *
     * @param fileName the file name to retrieve the file extension from.
     * @return the file extension.
     */
    @Nullable
    public static String getFileExtension(@NotNull String fileName) {
        @Nullable
        final String fileExt = FilenameUtils.getExtension(fileName);
        return StringUtils.isNoneEmpty(fileExt) ? StringUtils.lowerCase(fileExt) : null;
    }

    /**
     * Deletes a file. If the File is a directory it will recursively delete the
     * contents.
     *
     * @param file the File to delete
     * @return true if the file was deleted successfully, otherwise false
     */
    public static boolean delete(@Nullable File file) {
        if (file == null) {
            LOGGER.warn("cannot delete null File");
            return false;
        }

        try (Stream<Path> paths = Files.walk(file.toPath())) {
            paths.sorted(Comparator.reverseOrder())
            .map(Path::toFile)
            .forEach(File::delete);
        } catch (IOException ex) {
            LOGGER.trace(ex.getMessage(), ex);
            LOGGER.debug("Failed to delete file: {} (error message: {}); attempting to delete on exit.", file.getPath(), ex.getMessage());
            file.deleteOnExit();
            return false;
        }

        return true;
    }

    /**
     * Creates a unique temporary directory in the given directory.
     *
     * @param base the base directory to create a temporary directory within
     * @return the temporary directory
     * @throws java.io.IOException thrown when a directory cannot be created
     * within the base directory
     */
    @NotNull
    public static File createTempDirectory(@Nullable final File base) throws IOException {
        final File tempDir = new File(base, "dctemp" + UUID.randomUUID());
        if (tempDir.exists()) {
            return createTempDirectory(base);
        }
        if (!tempDir.mkdirs()) {
            throw new IOException("Could not create temp directory `" + tempDir.getAbsolutePath() + "`");
        }
        LOGGER.debug("Temporary directory is `{}`", tempDir.getAbsolutePath());
        return tempDir;
    }

    /**
     * Return the bit bucket for the OS. '/dev/null' for Unix and 'NUL' for
     * Windows
     *
     * @return a String containing the bit bucket
     */
    @NotNull
    public static String getBitBucket() {
        return SystemUtils.IS_OS_WINDOWS ? BIT_BUCKET_WIN : BIT_BUCKET_UNIX;
    }

    /**
     * Close the given {@link java.io.Closeable} instance, ignoring nulls, and
     * logging any thrown {@link java.io.IOException}.
     *
     * @param closeable to be closed
     */
    public static void close(@Nullable final Closeable closeable) {
        if (null != closeable) {
            try {
                closeable.close();
            } catch (IOException ex) {
                LOGGER.trace("", ex);
            }
        }
    }

    /**
     * Gets the {@link java.io.InputStream} for this resource.
     *
     * @param resource path
     * @return the input stream for the given resource
     * @throws FileNotFoundException if the file could not be found
     */
    public static InputStream getResourceAsStream(@NotNull String resource) throws FileNotFoundException {
        final ClassLoader classLoader = FileUtils.class.getClassLoader();
        final InputStream inputStream = classLoader != null
                ? classLoader.getResourceAsStream(resource)
                : ClassLoader.getSystemResourceAsStream(resource);

        if (inputStream == null) {
            return new FileInputStream(resource);
        }
        return inputStream;
    }

    /**
     * Returns a File object for the given resource. The resource is attempted
     * to be loaded from the class loader.
     *
     * @param resource path
     * @return the file reference for the resource
     */
    public static File getResourceAsFile(final String resource) {
        final ClassLoader classLoader = FileUtils.class.getClassLoader();
        String path = null;
        if (classLoader != null) {
            final URL url = classLoader.getResource(resource);
            if (url != null) {
                path = url.getFile();
            }
        } else {
            path = ClassLoader.getSystemResource(resource).getFile();
        }

        if (path == null) {
            return new File(resource);
        }
        return new File(path);
    }
}
