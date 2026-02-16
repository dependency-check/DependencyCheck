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
package org.owasp.dependencycheck.data.lucene;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

import org.apache.lucene.analysis.TokenFilter;
import org.apache.lucene.analysis.TokenStream;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.List;

public class TokenPairConcatenatingFilterTest extends BaseTokenFilterTest {

    @Test
    @Disabled("Has been broken since change to reset logic in 74ff6d99e78eaef15c595fe35d7ed12d8c22a7a9")
    public void testIncrementToken() throws Exception {
        assertThat(processAllFrom("red blue green"), contains("red", "redblue", "blue", "bluegreen", "green"));
    }

    @Override
    TokenFilter newFilter(@NonNull final TokenStream stream, List<String> terms) {
        return new TokenPairConcatenatingFilter(stream) {
            @Override
            protected void appendTerm(String term) {
                super.appendTerm(term);
                terms.add(term);
            }
        };
    }
}
