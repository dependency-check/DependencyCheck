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
package org.owasp.dependencycheck.utils;

import org.junit.jupiter.api.Test;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

/**
 *
 * @author jeremy
 */
class ExpectedObjectInputStreamTest {

    /**
     * Test of resolveClass method, of class ExpectedObjectInputStream.
     */
    @Test
    void testResolveClass() {
        List<SimplePojo> data = new ArrayList<>();
        data.add(new SimplePojo());
        try (ByteArrayOutputStream mem = new ByteArrayOutputStream();
                ObjectOutputStream out = new ObjectOutputStream(new BufferedOutputStream(mem))) {
            out.writeObject(data);
            out.flush();
            byte[] buf = mem.toByteArray();
            ByteArrayInputStream in = new ByteArrayInputStream(buf);
            ExpectedObjectInputStream instance = new ExpectedObjectInputStream(in, "java.util.ArrayList", "org.owasp.dependencycheck.utils.SimplePojo", "java.lang.Integer", "java.lang.Number");
            instance.readObject();
        } catch (IOException | ClassNotFoundException ex) {
            fail(ex.getMessage());
        }
    }

    /**
     * Test of resolveClass method, of class ExpectedObjectInputStream.
     */
    @Test
    void testResolveClassException() throws Exception {
        List<SimplePojo> data = new ArrayList<>();
        data.add(new SimplePojo());
        ByteArrayOutputStream mem = new ByteArrayOutputStream();
        byte[] buf;
        try (ObjectOutputStream out = new ObjectOutputStream(new BufferedOutputStream(mem))) {
            out.writeObject(data);
            out.flush();
            buf = mem.toByteArray();
        }
        ByteArrayInputStream in = new ByteArrayInputStream(buf);
        ExpectedObjectInputStream instance = new ExpectedObjectInputStream(in, "java.util.ArrayList", "org.owasp.dependencycheck.utils.SimplePojo");
        assertThrows(java.io.InvalidClassException.class, instance::readObject);
    }
}
