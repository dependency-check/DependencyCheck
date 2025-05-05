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
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 * @author Jeremy Long
 */
class InterpolationUtilTest {

    /**
     * Test of interpolate method, of class InterpolationUtil.
     */
    @Test
    void testInterpolate() {
        Properties prop = new Properties();
        prop.setProperty("key", "value");
        prop.setProperty("nested", "nested ${key}");
        String text = "This is a test of '${key}' '${nested}'";
        String expResults = "This is a test of 'value' 'nested value'";
        String results = InterpolationUtil.interpolate(text, prop);
        assertEquals(expResults, results);
    }

    @Test
    void testInterpolateNonexistentErased() {
        Properties prop = new Properties();
        prop.setProperty("key", "value");
        String text = "This is a test of '${key}' and '${nothing}'";
        String expResults = "This is a test of 'value' and ''";
        String results = InterpolationUtil.interpolate(text, prop);
        assertEquals(expResults, results);
    }

    @Test
    void testInterpolateMSBuild() {
        Properties prop = new Properties();
        prop.setProperty("key", "value");
        prop.setProperty("nested", "nested $(key)");
        String text = "This is a test of '$(key)' '$(nested)'";
        String expResults = "This is a test of 'value' 'nested value'";
        String results = InterpolationUtil.interpolate(text, prop, InterpolationUtil.SyntaxStyle.MSBUILD);
        assertEquals(expResults, results);
    }

    @Test
    void testInterpolateNonexistentErasedMSBuild() {
        Properties prop = new Properties();
        prop.setProperty("key", "value");
        String text = "This is a test of '$(key)' and '$(nothing)'";
        String expResults = "This is a test of 'value' and ''";
        String results = InterpolationUtil.interpolate(text, prop, InterpolationUtil.SyntaxStyle.MSBUILD);
        assertEquals(expResults, results);
    }
}
