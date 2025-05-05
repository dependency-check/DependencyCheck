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
 * Copyright (c) 2015 The OWASP Foundatio. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.composer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Created by colezlaw on 9/5/15.
 */
class ComposerLockParserTest extends BaseTest {

    private InputStream inputStream;

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        inputStream = this.getClass().getClassLoader().getResourceAsStream("composer.lock");
    }

    @Test
    void testValidComposerLock() {
        ComposerLockParser clp = new ComposerLockParser(inputStream, false);
        clp.process();
        assertEquals(30, clp.getDependencies().size());
        assertTrue(clp.getDependencies().contains(new ComposerDependency("symfony", "translation", "2.7.3")));
        assertTrue(clp.getDependencies().contains(new ComposerDependency("vlucas", "phpdotenv", "1.1.1")));
    }


    @Test
    void testComposerLockSkipDev() {
        ComposerLockParser clp = new ComposerLockParser(inputStream, true);
        clp.process();
        assertEquals(29, clp.getDependencies().size());
        assertTrue(clp.getDependencies().contains(new ComposerDependency("symfony", "translation", "2.7.3")));
        //vlucas/phpdotenv is in packages-dev
        assertFalse(clp.getDependencies().contains(new ComposerDependency("vlucas", "phpdotenv", "1.1.1")));
    }

    @Test
    void testNotJSON() {
        String input = "NOT VALID JSON";
        ComposerLockParser clp = new ComposerLockParser(new ByteArrayInputStream(input.getBytes(Charset.defaultCharset())), false);
        assertThrows(ComposerException.class, clp::process);
    }

    @Test
    void testNotComposer() {
        String input = "[\"ham\",\"eggs\"]";
        ComposerLockParser clp = new ComposerLockParser(new ByteArrayInputStream(input.getBytes(Charset.defaultCharset())), false);
        assertThrows(ComposerException.class, clp::process);
    }

    @Test
    void testNotPackagesArray() {
        String input = "{\"packages\":\"eleventy\"}";
        ComposerLockParser clp = new ComposerLockParser(new ByteArrayInputStream(input.getBytes(Charset.defaultCharset())), false);
        assertThrows(ComposerException.class, clp::process);
    }
}
