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
package org.owasp.dependencycheck.data.lucene;

import org.apache.lucene.analysis.CharArraySet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author jeremy long
 */
class SearchFieldAnalyzerTest {

    /**
     * Test of getStopWords method, of class SearchFieldAnalyzer.
     */
    @Test
    void testGetStopWords() {
        CharArraySet result = SearchFieldAnalyzer.getStopWords();
        assertTrue(result.size() > 20);
        assertTrue(result.contains("software"));
    }
}
