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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.Date;
import javax.annotation.concurrent.NotThreadSafe;
import org.owasp.dependencycheck.exception.WriteLockException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A lock file implementation; creates a custom lock file so that only a single
 * instance of dependency-check can update the a given resource.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class WriteLock implements AutoCloseable {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(WriteLock.class);
    /**
     * Secure random number generator.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    /**
     * How long to sleep waiting for the lock.
     */
    public static final int SLEEP_DURATION = 15000;
    /**
     * Max attempts to obtain a lock.
     */
    public static final int MAX_SLEEP_COUNT = 160;
    /**
     * The file lock.
     */
    private FileLock lock = null;
    /**
     * Reference to the file that we are locking.
     */
    private RandomAccessFile file = null;
    /**
     * The lock file.
     */
    private File lockFile = null;
    /**
     * The configured settings.
     */
    private final Settings settings;
    /**
     * A random string used to validate the lock.
     */
    private final String magic;
    /**
     * A flag indicating whether or not an resource is lockable.
     */
    private final boolean isLockable;
    /**
     * The name of the lock file.
     */
    private final String lockFileName;
    /**
     * The shutdown hook used to remove the lock file in case of an unexpected
     * shutdown.
     */
    private WriteLockShutdownHook hook = null;

    /**
     * Constructs a new Write Lock object with the configured settings.
     *
     * @param settings the configured settings
     * @throws WriteLockException thrown if a lock could not be obtained
     */
    public WriteLock(Settings settings) throws WriteLockException {
        this(settings, true);
    }

    /**
     * Constructs a new Write Lock object with the configured settings.
     *
     * @param settings the configured settings
     * @param isLockable a flag indicating if a lock can be obtained for the
     * resource; if false the lock does nothing. This is useful in the case of
     * ODC where we need to lock for updates against H2 but we do not need to
     * lock updates for other databases.
     * @throws WriteLockException thrown if a lock could not be obtained
     */
    public WriteLock(Settings settings, boolean isLockable) throws WriteLockException {
        this(settings, isLockable, "odc.update.lock");
    }

    /**
     * Constructs a new Write Lock object with the configured settings.
     *
     * @param settings the configured settings
     * @param isLockable a flag indicating if a lock can be obtained for the
     * resource; if false the lock does nothing. This is useful in the case of
     * ODC where we need to lock for updates against H2 but we do not need to
     * lock updates for other databases.
     * @param lockFileName the name of the lock file; note the lock file will be
     * in the ODC data directory.
     * @throws WriteLockException thrown if a lock could not be obtained
     */
    public WriteLock(Settings settings, boolean isLockable, String lockFileName) throws WriteLockException {
        this.settings = settings;
        final byte[] random = new byte[16];
        SECURE_RANDOM.nextBytes(random);
        magic = Checksum.getHex(random);
        this.isLockable = isLockable;
        this.lockFileName = lockFileName;
        lock();
    }

    /**
     * Obtains a lock on the resource.
     *
     * @throws WriteLockException thrown if a lock could not be obtained
     */
    public final void lock() throws WriteLockException {
        if (!isLockable) {
            return;
        }
        final File dir = new File(System.getProperty("java.io.tmpdir"));
        lockFile = new File(dir, lockFileName);
        checkState();
        int ctr = 0;
        do {
            try {
                if (!lockFile.exists() && lockFile.createNewFile()) {
                    file = new RandomAccessFile(lockFile, "rw");
                    lock = file.getChannel().lock();
                    file.writeBytes(magic);
                    file.getChannel().force(true);
                    Thread.sleep(20);
                    file.seek(0);
                    final String current = file.readLine();
                    if (current != null && !current.equals(magic)) {
                        lock.close();
                        lock = null;
                        LOGGER.debug("Another process obtained a lock first ({})", Thread.currentThread().getName());
                    } else {
                        addShutdownHook();
                        final Timestamp timestamp = new Timestamp(System.currentTimeMillis());
                        LOGGER.debug("Lock file created ({}) {} @ {}", Thread.currentThread().getName(), magic, timestamp);
                    }
                }
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                LOGGER.trace("Expected error as another thread has likely locked the file", ex);
            } catch (IOException ex) {
                LOGGER.trace("Expected error as another thread has likely locked the file", ex);
            } finally {
                if (lock == null && file != null) {
                    try {
                        file.close();
                        file = null;
                    } catch (IOException ex) {
                        LOGGER.trace("Unable to close the lock file", ex);
                    }
                }
            }
            if (lock == null || !lock.isValid()) {
                try {
                    final Timestamp timestamp = new Timestamp(System.currentTimeMillis());
                    LOGGER.debug("Sleeping thread {} ({}) for {} seconds because an exclusive lock on the database could not be obtained ({})",
                            Thread.currentThread().getName(), magic, SLEEP_DURATION / 1000, timestamp);
                    Thread.sleep(SLEEP_DURATION);
                } catch (InterruptedException ex) {
                    LOGGER.debug("sleep was interrupted.", ex);
                    Thread.currentThread().interrupt();
                }
            }
        } while (++ctr < MAX_SLEEP_COUNT && (lock == null || !lock.isValid()));
        if (lock == null || !lock.isValid()) {
            throw new WriteLockException("Unable to obtain the update lock, skipping the database update. Skipping the database update.");
        }
    }

    /**
     * Releases the lock on the resource.
     */
    @Override
    public void close() {
        if (!isLockable) {
            return;
        }
        if (lock != null) {
            try {
                lock.release();
                lock = null;
            } catch (IOException ex) {
                LOGGER.debug("Failed to release lock", ex);
            }
        }
        if (file != null) {
            try {
                file.close();
                file = null;
            } catch (IOException ex) {
                LOGGER.debug("Unable to delete lock file", ex);
            }
        }
        if (lockFile != null && lockFile.isFile()) {
            final String msg = readLockFile();
            if (msg != null && msg.equals(magic) && !lockFile.delete()) {
                LOGGER.error("Lock file '{}' was unable to be deleted. Please manually delete this file.", lockFile.toString());
                lockFile.deleteOnExit();
            }
        }
        lockFile = null;
        removeShutdownHook();
        final Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        LOGGER.debug("Lock released ({}) {} @ {}", Thread.currentThread().getName(), magic, timestamp);
    }

    /**
     * Checks the state of the custom write lock file and under some conditions
     * will attempt to remove the lock file.
     *
     * @throws WriteLockException thrown if the lock directory does not exist
     * and cannot be created
     */
    private void checkState() throws WriteLockException {
        if (!lockFile.getParentFile().isDirectory() && !lockFile.mkdir()) {
            throw new WriteLockException("Unable to create path to data directory.");
        }
        if (lockFile.isFile()) {
            //TODO - this 30 minute check needs to be configurable.
            if (getFileAge(lockFile) > 30) {
                LOGGER.debug("An old write lock file was found: {}", lockFile.getAbsolutePath());
                if (!lockFile.delete()) {
                    LOGGER.warn("An old write lock file was found but the system was unable to delete "
                            + "the file. Consider manually deleting {}", lockFile.getAbsolutePath());
                }
            } else {
                LOGGER.info("Lock file found `{}`", lockFile);
                LOGGER.info("Existing update in progress; waiting for update to complete");
            }
        }
    }

    /**
     * Reads the first line from the lock file and returns the results as a
     * string.
     *
     * @return the first line from the lock file; or null if the contents could
     * not be read
     */
    private String readLockFile() {
        String msg = null;
        try (RandomAccessFile f = new RandomAccessFile(lockFile, "rw")) {
            msg = f.readLine();
        } catch (IOException ex) {
            LOGGER.debug(String.format("Error reading lock file: %s", lockFile), ex);
        }
        return msg;
    }

    /**
     * Returns the age of the file in minutes.
     *
     * @param file the file to calculate the age
     * @return the age of the file
     */
    private double getFileAge(File file) {
        final Date d = new Date();
        final long modified = file.lastModified();
        final double time = (d.getTime() - modified) / 1000.0 / 60.0;
        LOGGER.debug("Lock file age is {} minutes", time);
        return time;
    }

    /**
     * Adds the shutdown hook to the JVM.
     */
    private void addShutdownHook() {
        if (hook == null) {
            hook = WriteLockShutdownHookFactory.getHook(settings);
            hook.add(this);

        }
    }

    /**
     * Removes the shutdown hook.
     */
    private void removeShutdownHook() {
        if (hook != null) {
            hook.remove();
            hook = null;
        }
    }
}
