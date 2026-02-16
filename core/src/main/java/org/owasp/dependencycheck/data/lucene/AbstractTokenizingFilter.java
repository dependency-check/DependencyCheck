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

import java.io.IOException;
import java.util.ArrayDeque;
import javax.annotation.concurrent.NotThreadSafe;
import org.apache.lucene.analysis.TokenFilter;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;

/**
 * An abstract tokenizing filter that can be used as the base for a tokenizing
 * filter.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public abstract class AbstractTokenizingFilter extends TokenFilter {

    /**
     * The char term attribute.
     */
    private final CharTermAttribute termAtt = addAttribute(CharTermAttribute.class);

    /**
     * A collection of tokens to add to the stream.
     */
    private final ArrayDeque<String> tokens;

    /**
     * Gets the CharTermAttribute.
     *
     * @return the CharTermAttribute
     */
    protected CharTermAttribute getTermAtt() {
        return termAtt;
    }

    /**
     * Gets the list of tokens.
     *
     * @return the list of tokens
     */
    protected ArrayDeque<String> getTokens() {
        return tokens;
    }

    /**
     * Constructs a new AbstractTokenizingFilter.
     *
     * @param stream the TokenStream that this filter will process
     */
    public AbstractTokenizingFilter(TokenStream stream) {
        super(stream);
        tokens = new ArrayDeque<>();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void reset() throws IOException {
        super.reset();
        tokens.clear();
    }

    /**
     * Adds a term, if one exists, from the tokens collection.
     *
     * @return whether or not a new term was added
     */
    protected boolean addTerm() {
        final boolean termAdded = !tokens.isEmpty();
        if (termAdded) {
            final String term = tokens.pop();
            clearAttributes();
            appendTerm(term);
        }
        return termAdded;
    }

    protected void appendTerm(String term) {
        termAtt.append(term);
    }
}
