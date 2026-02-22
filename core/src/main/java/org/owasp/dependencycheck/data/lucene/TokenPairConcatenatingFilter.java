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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.lucene;

import java.io.IOException;
import javax.annotation.concurrent.NotThreadSafe;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.lucene.analysis.TokenFilter;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;

/**
 * <p>
 * Takes a TokenStream and adds additional tokens by concatenating pairs of
 * words.</p>
 * <p>
 * <b>Example:</b> "Spring Framework Core" -&gt; "Spring SpringFramework
 * Framework FrameworkCore Core".</p>
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class TokenPairConcatenatingFilter extends TokenFilter {

    /**
     * The char term attribute.
     */
    private final CharTermAttribute termAtt = addAttribute(CharTermAttribute.class);
    /**
     * The previous word parsed.
     */
    private String previousWord;
    /**
     * Keeps track if we are adding a single term or concatenating with the
     * previous.
     */
    private boolean addSingleTerm;

    /**
     * Constructs a new TokenPairConcatenatingFilter.
     *
     * @param stream the TokenStream that this filter will process
     */
    public TokenPairConcatenatingFilter(TokenStream stream) {
        super(stream);
        addSingleTerm = true;
        previousWord = null;
    }

    /**
     * Increments the underlying TokenStream and sets CharTermAttributes to
     * construct an expanded set of tokens by concatenating tokens with the
     * previous token.
     *
     * @return whether or not we have hit the end of the TokenStream
     * @throws IOException is thrown when an IOException occurs
     */
    @Override
    public final boolean incrementToken() throws IOException {
        if (addSingleTerm && previousWord != null) {
            addSingleTerm = false;
            clearAttributes();
            appendTerm(previousWord);
            return true;

        } else if (input.incrementToken()) {
            final String word = new String(termAtt.buffer(), 0, termAtt.length());
            if (word.isEmpty()) {
                return true;
            }
            if (addSingleTerm) {
                clearAttributes();
                appendTerm(word);
                previousWord = word;
                addSingleTerm = false;
            } else {
                clearAttributes();
                appendTerm(previousWord);
                appendTerm(word);
                previousWord = word;
                addSingleTerm = true;
            }
            return true;
        }
        return false;
    }

    protected void appendTerm(String term) {
        termAtt.append(term);
    }

    /**
     * Resets the filter. This must be manually called between searching and
     * indexing. Unable to rely on `reset` as it appears to be called between
     * terms.
     *
     * @throws IOException thrown if there is an error reseting the tokenizer
     */
    public void clear() throws IOException {
        previousWord = null;
        addSingleTerm = true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(13, 27)
                .appendSuper(super.hashCode())
                .append(addSingleTerm)
                .append(previousWord)
                .append(termAtt)
                .build();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof TokenPairConcatenatingFilter)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final TokenPairConcatenatingFilter rhs = (TokenPairConcatenatingFilter) obj;
        return new EqualsBuilder()
                .appendSuper(super.equals(obj))
                .append(addSingleTerm, rhs.addSingleTerm)
                .append(previousWord, rhs.previousWord)
                .append(termAtt, rhs.termAtt)
                .isEquals();
    }
}
