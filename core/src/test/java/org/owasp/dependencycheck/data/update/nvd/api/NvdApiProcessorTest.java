/*
 * Copyright 2014 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.data.update.nvd.api;

import com.fasterxml.jackson.core.JsonParseException;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nvdcve.CveDB;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.NoSuchFileException;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 *
 * @author Jeremy Long
 */
class NvdApiProcessorTest extends BaseTest {

    @Test
    void doesNotExistFile() {
        try (CveDB cve = new CveDB(getSettings())) {
            File file = new File("does_not_exist");
            NvdApiProcessor processor = new NvdApiProcessor(null, file);
            assertThrows(NoSuchFileException.class, processor::call);
        }
    }

    @Test
    void unspecifiedFileName() throws Exception {
        try (CveDB cve = new CveDB(getSettings())) {
            File file = File.createTempFile("test", "test");
            writeFileString(file, "");
            NvdApiProcessor processor = new NvdApiProcessor(null, file);
            processor.call();
        }
    }

    @Test
    void invalidFileContent() throws Exception {
        try (CveDB cve = new CveDB(getSettings())) {
            File file = File.createTempFile("test", "test.json");
            // invalid content (broken array)
            writeFileString(file, "[}");
            NvdApiProcessor processor = new NvdApiProcessor(null, file);
            assertThrows(JsonParseException.class, processor::call);
        }
    }

    @Test
    void processValidStructure() throws Exception {
        try (CveDB cve = new CveDB(getSettings())) {
            File file = File.createTempFile("test", "test.json");
            writeFileString(file, "[]");
            NvdApiProcessor processor = new NvdApiProcessor(null, file);
            processor.call();
        }
    }

    static void writeFileString(File file, String content) throws IOException {
        try (FileWriter writer = new FileWriter(file, false)) {
            writer.write(content);
            writer.flush();
        }
    }
}
