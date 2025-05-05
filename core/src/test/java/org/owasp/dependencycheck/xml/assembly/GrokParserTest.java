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
package org.owasp.dependencycheck.xml.assembly;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test of the Grok Assembly parser.
 *
 * @author Jeremy Long
 */
class GrokParserTest extends BaseTest {

    @Test
    void testParseSuppressionRulesV1dot0() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "assembly/sample-grok-error.xml");
        GrokParser instance = new GrokParser();
        AssemblyData result = instance.parse(file);
        assertEquals("Unable to process file", result.getError());
    }
}
