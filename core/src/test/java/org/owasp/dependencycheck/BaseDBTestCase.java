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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.owasp.dependencycheck.data.nvdcve.DatabaseManager;
import org.owasp.dependencycheck.utils.WriteLock;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An abstract database test case that is used to ensure the H2 DB exists prior
 * to performing tests that utilize the data contained within.
 *
 * @author Jeremy Long
 */
public abstract class BaseDBTestCase extends BaseTest {

    protected final static int BUFFER_SIZE = 2048;

    private final static Logger LOGGER = LoggerFactory.getLogger(BaseDBTestCase.class);

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        synchronized (this) {
            ensureDBExists();
        }
    }

    public void ensureDBExists() throws Exception {
        try (WriteLock dblock = new WriteLock(getSettings(), DatabaseManager.isH2Connection(getSettings()))) {
            File f = new File("./target/data/odc.mv.db");
            if (f.exists() && f.isFile() && f.length() < 71680) {
                f.delete();
            }
            File dataPath = getSettings().getH2DataDirectory();
            String fileName = getSettings().getString(Settings.KEYS.DB_FILE_NAME);
            LOGGER.trace("DB file name {}", fileName);
            File dataFile = new File(dataPath, fileName);
            LOGGER.trace("Ensuring {} exists", dataFile);
            if (!dataPath.exists() || !dataFile.exists()) {
                LOGGER.trace("Extracting database to {}", dataPath);
                dataPath.mkdirs();
                File path = new File(BaseDBTestCase.class.getClassLoader().getResource("data.zip").toURI().getPath());
                try (FileInputStream fis = new FileInputStream(path);
                        ZipInputStream zin = new ZipInputStream(new BufferedInputStream(fis))) {
                    ZipEntry entry;
                    while ((entry = zin.getNextEntry()) != null) {
                        if (entry.isDirectory()) {
                            final File d = new File(dataPath, entry.getName());
                            d.mkdir();
                            continue;
                        }
                        //File o = new File(dataPath, entry.getName());
                        //o.createNewFile();
                        dataFile.createNewFile();
                        try (FileOutputStream fos = new FileOutputStream(dataFile, false);
                                BufferedOutputStream dest = new BufferedOutputStream(fos, BUFFER_SIZE)) {
                            IOUtils.copy(zin, dest);
                        } catch (Throwable ex) {
                            LOGGER.error("", ex);
                        }
                    }
                }
                //update the schema
                DatabaseManager factory = new DatabaseManager(getSettings());
            }
        }
    }
}
