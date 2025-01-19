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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.util.Arrays;
import jakarta.json.JsonReader;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import static org.junit.Assert.assertFalse;
import org.junit.Before;
import org.junit.BeforeClass;

/**
 *
 * @author Jeremy Long
 */
public class JsonArrayFixingInputStreamTest {

    final String sample1 = "{}";
    final String sample2 = "{}{}";
    final String sample3 = "{'key'='value'}{'key'='value'}\n";
    final String sample4 = "{\n"
            + "	\"Path\": \"my/thing\",\n"
            + "	\"Main\": true,\n"
            + "	\"Dir\": \"/Users/jeremy/Projects/DependencyCheck/core/target/test-classes/golang\",\n"
            + "	\"GoMod\": \"/Users/jeremy/Projects/DependencyCheck/core/target/test-classes/golang/go.mod\"\n"
            + "}\n"
            + "{\n"
            + "	\"Path\": \"github.com/ethereum/go-ethereum\",\n"
            + "	\"Version\": \"v1.8.17\",\n"
            + "	\"Time\": \"2018-10-09T07:35:31Z\",\n"
            + "	\"GoMod\": \"/Users/jeremy/go/pkg/mod/cache/download/github.com/ethereum/go-ethereum/@v/v1.8.17.mod\"\n"
            + "}\n"
            + "{\n"
            + "	\"Path\": \"github.com/go-gitea/gitea\",\n"
            + "	\"Version\": \"v1.5.0\",\n"
            + "	\"Time\": \"2018-08-10T17:16:53Z\",\n"
            + "	\"GoMod\": \"/Users/jeremy/go/pkg/mod/cache/download/github.com/go-gitea/gitea/@v/v1.5.0.mod\"\n"
            + "}\n"
            + "{\n"
            + "	\"Path\": \"golang.org/x/crypto\",\n"
            + "	\"Version\": \"v0.0.0-20200820211705-5c72a883971a\",\n"
            + "	\"Time\": \"2020-08-20T21:17:05Z\",\n"
            + "	\"Indirect\": true,\n"
            + "	\"Dir\": \"/Users/jeremy/go/pkg/mod/golang.org/x/crypto@v0.0.0-20200820211705-5c72a883971a\",\n"
            + "	\"GoMod\": \"/Users/jeremy/go/pkg/mod/cache/download/golang.org/x/crypto/@v/v0.0.0-20200820211705-5c72a883971a.mod\",\n"
            + "	\"GoVersion\": \"1.11\"\n"
            + "}\n"
            + "{\n"
            + "	\"Path\": \"golang.org/x/net\",\n"
            + "	\"Version\": \"v0.0.0-20190404232315-eb5bcb51f2a3\",\n"
            + "	\"Time\": \"2019-04-04T23:23:15Z\",\n"
            + "	\"Indirect\": true,\n"
            + "	\"GoMod\": \"/Users/jeremy/go/pkg/mod/cache/download/golang.org/x/net/@v/v0.0.0-20190404232315-eb5bcb51f2a3.mod\"\n"
            + "}\n"
            + "{\n"
            + "	\"Path\": \"golang.org/x/sys\",\n"
            + "	\"Version\": \"v0.0.0-20190412213103-97732733099d\",\n"
            + "	\"Time\": \"2019-04-12T21:31:03Z\",\n"
            + "	\"Indirect\": true,\n"
            + "	\"GoMod\": \"/Users/jeremy/go/pkg/mod/cache/download/golang.org/x/sys/@v/v0.0.0-20190412213103-97732733099d.mod\",\n"
            + "	\"GoVersion\": \"1.12\"\n"
            + "}\n"
            + "{\n"
            + "	\"Path\": \"golang.org/x/text\",\n"
            + "	\"Version\": \"v0.3.0\",\n"
            + "	\"Time\": \"2017-12-14T13:08:43Z\",\n"
            + "	\"Indirect\": true,\n"
            + "	\"GoMod\": \"/Users/jeremy/go/pkg/mod/cache/download/golang.org/x/text/@v/v0.3.0.mod\"\n"
            + "}\n"
            + "{\n"
            + " \"Path\": \"github.com/Microsoft/hcsshim\",\n"
            + " \"Version\": \"v0.8.7\",\n"
            + " \"Replace\": {\n"
            + " \"Path\": \"github.com/Microsoft/hcsshim\",\n"
            + " \"Version\": \"v0.8.8-0.20200421182805-c3e488f0d815\",\n"
            + " \"Time\": \"2020-04-21T18:28:05Z\",\n"
            + " \"GoMod\": \"/Users/me/go/pkg/mod/cache/download/github.com/!microsoft/hcsshim/@v/v0.8.8-0.20200421182805-c3e488f0d815.mod\"\n"
            + "},\n"
            + "	\"Indirect\": true,\n"
            + "\"GoMod\": \"/Users/me/go/pkg/mod/cache/download/github.com/!microsoft/hcsshim/@v/v0.8.8-0.20200421182805-c3e488f0d815.mod\"\n"
            + "}\n";

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    /**
     * Test of read method, of class JsonArrayFixingInputStream.
     *
     * @throws Exception because one might happen
     */
    @Test
    public void testRead_0args() throws Exception {
        try (InputStream sample = new ByteArrayInputStream(sample1.getBytes());
                JsonArrayFixingInputStream instance = new JsonArrayFixingInputStream(sample)) {
            assertEquals('[', instance.read());
            assertEquals('{', instance.read());
            assertEquals('}', instance.read());
            assertEquals(']', instance.read());
            assertEquals(-1, instance.read());
        }

        try (InputStream sample = new ByteArrayInputStream(sample2.getBytes());
                JsonArrayFixingInputStream instance = new JsonArrayFixingInputStream(sample)) {
            assertEquals('[', instance.read());
            assertEquals('{', instance.read());
            assertEquals('}', instance.read());
            assertEquals(',', instance.read());
            assertEquals('{', instance.read());
            assertEquals('}', instance.read());
            assertEquals(']', instance.read());
            assertEquals(-1, instance.read());
        }
    }

    /**
     * Test of read method, of class JsonArrayFixingInputStream.
     *
     * @throws Exception because one might happen
     */
    @Test
    public void testRead_byteArr() throws Exception {
        byte[] b = new byte[9];
        try (InputStream sample = new ByteArrayInputStream(sample2.getBytes());
                JsonArrayFixingInputStream instance = new JsonArrayFixingInputStream(sample)) {
            int read = instance.read(b);
            assertEquals(2, read);
            assertEquals('[', b[0]);
            assertEquals('{', b[1]);

            read = instance.read(b);
            assertEquals(1, read);
            assertEquals('}', b[0]);

            read = instance.read(b);
            assertEquals(2, read);
            assertEquals(',', b[0]);
            assertEquals('{', b[1]);

            read = instance.read(b);
            assertEquals(1, read);
            assertEquals('}', b[0]);

            read = instance.read(b);
            assertEquals(1, read);
            assertEquals(']', b[0]);
        }
    }

    @Test()
    public void testRead_IOUtils() throws Exception {
        try (InputStream sample = new ByteArrayInputStream(sample3.getBytes());
                JsonArrayFixingInputStream instance = new JsonArrayFixingInputStream(sample)) {
            String results = IOUtils.toString(instance, UTF_8);
            assertEquals("[{'key'='value'},{'key'='value'}]", results);

        }
    }

    @Test()
    public void testRead_RealSample() throws Exception {
        try (InputStream sample = new ByteArrayInputStream(sample4.getBytes());
                JsonArrayFixingInputStream instance = new JsonArrayFixingInputStream(sample)) {
            try (JsonReader reader = Json.createReader(instance)) {
                final JsonArray modules = reader.readArray();
                assertEquals(8, modules.size());
            }
        }
    }

    /**
     * Test boundary conditions of the buffer window
     *
     * @throws Exception because one might happen
     */
    @Test()
    public void testRead_3args() throws Exception {
        byte[] input = new byte[2048];
        Arrays.fill(input, (byte) ' ');
        input[0] = '{';
        input[2047] = '}';
        byte[] results = new byte[2050];
        byte[] expected = new byte[2050];
        Arrays.fill(expected, (byte) ' ');
        expected[0] = '[';
        expected[1] = '{';
        expected[2048] = '}';
        expected[2049] = ']';
        try (InputStream sample = new ByteArrayInputStream(input);
                JsonArrayFixingInputStream instance = new JsonArrayFixingInputStream(sample)) {
            int read = 0;
            int pos = 0;
            while (read >= 0) {
                read = instance.read(results, pos, 2050 - pos);
                pos += read;
            }
            Assert.assertArrayEquals(expected, results);
        }
    }

    /**
     * Test of skip method, of class JsonArrayFixingInputStream.
     *
     * @throws Exception because one might happen
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testSkip() throws Exception {
        try (InputStream sample = new ByteArrayInputStream(sample1.getBytes());
                JsonArrayFixingInputStream instance = new JsonArrayFixingInputStream(sample)) {
            instance.skip(1);
        }
    }

    /**
     * Test of available method, of class JsonArrayFixingInputStream.
     *
     * @throws Exception because one might happen
     */
    @Test
    public void testAvailable() throws Exception {
        try (InputStream sample = new ByteArrayInputStream(sample1.getBytes());
                JsonArrayFixingInputStream instance = new JsonArrayFixingInputStream(sample)) {
            int results = instance.available();
            assertTrue(results > 0);
            String text = IOUtils.toString(instance, UTF_8);
            int i = instance.read();
            assertEquals(-1, i);
            //odd buffer is 0 and we've read to the end - but available on the underlying stream still says 3...
            //results = instance.available();
            //assertEquals(0, results);
        }
    }

    /**
     * Test of close method, of class JsonArrayFixingInputStream.
     *
     * @throws Exception because one might happen
     */
    @Test
    public void testClose() throws Exception {
        try (InputStream sample = new ByteArrayInputStream(sample1.getBytes());
                JsonArrayFixingInputStream instance = new JsonArrayFixingInputStream(sample)) {
            int i = instance.read();
        }
    }

    /**
     * Test of markSupported method, of class JsonArrayFixingInputStream.
     *
     * @throws Exception because one might happen
     */
    @Test
    public void testMarkSupported() throws Exception {
        try (InputStream sample = new ByteArrayInputStream(sample1.getBytes());
                JsonArrayFixingInputStream instance = new JsonArrayFixingInputStream(sample)) {
            boolean result = instance.markSupported();
            assertFalse(result);
        }
    }

    @Test
    public void testIsWhiteSpace() throws Exception {
        JsonArrayFixingInputStream instance = new JsonArrayFixingInputStream(null);
        assertFalse(instance.isWhiteSpace((byte) 'a'));
        assertTrue(instance.isWhiteSpace((byte) '\n'));
        assertTrue(instance.isWhiteSpace((byte) '\t'));
        assertTrue(instance.isWhiteSpace((byte) '\r'));
        assertTrue(instance.isWhiteSpace((byte) ' '));
    }

}
