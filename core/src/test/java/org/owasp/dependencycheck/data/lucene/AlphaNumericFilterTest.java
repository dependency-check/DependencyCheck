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

import org.apache.lucene.analysis.TokenFilter;
import org.apache.lucene.analysis.TokenStream;
import org.hamcrest.Matchers;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;

/**
 *
 * @author Jeremy Long
 */
public class AlphaNumericFilterTest extends BaseTokenFilterTest {

    @Test
    public void testIncrementToken() throws Exception {
        assertThat(processAllFrom("http://www.domain.com/test.php"), Matchers.contains("http", "www", "domain", "com", "test", "php"));
    }

    @Test
    public void testGarbage() throws Exception {
        assertThat(processAllFrom("!@#$% !@#$ &*(@#$ test-two @#$%"), Matchers.contains("test", "two"));
    }

    @Override
    TokenFilter newFilter(@NonNull final TokenStream stream, List<String> terms) {
        return new AlphaNumericFilter(stream) {
            @Override
            protected void appendTerm(String term) {
                super.appendTerm(term);
                terms.add(term);
            }
        };
    }
}
