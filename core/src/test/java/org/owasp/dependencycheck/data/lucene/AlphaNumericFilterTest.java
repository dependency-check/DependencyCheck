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

import java.io.IOException;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.tests.analysis.BaseTokenStreamTestCase;
import static org.apache.lucene.tests.analysis.BaseTokenStreamTestCase.checkOneTerm;
import static org.apache.lucene.tests.analysis.BaseTokenStreamTestCase.checkRandomData;
import org.apache.lucene.tests.analysis.MockTokenizer;
import org.apache.lucene.analysis.Tokenizer;
import org.apache.lucene.analysis.core.KeywordTokenizer;
import static org.apache.lucene.tests.util.LuceneTestCase.RANDOM_MULTIPLIER;
import static org.apache.lucene.tests.util.LuceneTestCase.random;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

/**
 *
 * @author Jeremy Long
 */
public class AlphaNumericFilterTest extends BaseTokenStreamTestCase {

    private Analyzer analyzer;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new Analyzer() {
            @Override
            protected Analyzer.TokenStreamComponents createComponents(String fieldName) {
                Tokenizer source = new MockTokenizer(MockTokenizer.WHITESPACE, false);
                return new Analyzer.TokenStreamComponents(source, new AlphaNumericFilter(source));
            }
        };
    }

    /**
     * Test of incrementToken method, of class AlphaNumericFilter.
     * 
     * @throws Exception thrown if there is a problem
     */
    @Test
    public void testIncrementToken() throws Exception {
        String[] expected = new String[6];
        expected[0] = "http";
        expected[1] = "www";
        expected[2] = "domain";
        expected[3] = "com";
        expected[4] = "test";
        expected[5] = "php";
        assertAnalyzesTo(analyzer, "http://www.domain.com/test.php", expected);
    }

    /**
     * Test of incrementToken method, of class AlphaNumericFilter.
     *
     * @throws Exception thrown if there is a problem
     */
    @Test
    public void testGarbage() throws Exception {
        String[] expected = new String[2];
        expected[0] = "test";
        expected[1] = "two";
        assertAnalyzesTo(analyzer, "!@#$% !@#$ &*(@#$ test-two @#$%", expected);
    }

    /**
     * copied from
     * http://svn.apache.org/repos/asf/lucene/dev/trunk/lucene/analysis/common/src/test/org/apache/lucene/analysis/en/TestEnglishMinimalStemFilter.java
     * blast some random strings through the analyzer
     */
    @Test
    public void testRandomStrings() {
        try {
            checkRandomData(random(), analyzer, 1000 * RANDOM_MULTIPLIER);
        } catch (IOException ex) {
            fail("Failed test random strings: " + ex.getMessage());
        }
    }

    /**
     * copied from
     * http://svn.apache.org/repos/asf/lucene/dev/trunk/lucene/analysis/common/src/test/org/apache/lucene/analysis/en/TestEnglishMinimalStemFilter.java
     *
     * @throws IOException
     */
    @Test
    public void testEmptyTerm() throws IOException {
        Analyzer a = new Analyzer() {
            @Override
            protected Analyzer.TokenStreamComponents createComponents(String fieldName) {
                Tokenizer tokenizer = new KeywordTokenizer();
                return new Analyzer.TokenStreamComponents(tokenizer, new AlphaNumericFilter(tokenizer));
            }
        };
        checkOneTerm(a, "", "");
    }
}
