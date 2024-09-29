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
import java.util.ArrayDeque;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;
import org.apache.lucene.analysis.tokenattributes.PositionIncrementAttribute;

/**
 * A simple alphanumeric filter that removes non-alphanumeric characters from
 * the terms. If a term contains a non-alphanumeric character it may be split
 * into multiple terms.
 *
 * <table>
 * <caption>Filtering examples</caption>
 * <tr><th>term</th><th>results in</th></tr>
 * <tr><td>bob</td><td>bob</td></tr>
 * <tr><td>bob-cat</td><td>bob cat</td></tr>
 * <tr><td>#$%</td><td>[skipped]</td></tr>
 * </table>
 *
 * @author jeremy long
 */
public final class AlphaNumericFilter extends AbstractTokenizingFilter {

    /**
     * The position increment attribute.
     */
    private final PositionIncrementAttribute posIncrementAttribute = addAttribute(PositionIncrementAttribute.class);
    /**
     * Used to count the number of terms skipped as they were only made up of
     * special characters.
     */
    private int skipCounter;

    /**
     * Constructs a new AlphaNumericFilter.
     *
     * @param stream the TokenStream that this filter will process
     */
    public AlphaNumericFilter(TokenStream stream) {
        super(stream);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean incrementToken() throws IOException {
        final ArrayDeque<String> tokens = getTokens();
        final CharTermAttribute termAtt = getTermAtt();
        if (tokens.isEmpty()) {
            String[] parts;
            skipCounter = 0;
            while (input.incrementToken()) {
                final String text = new String(termAtt.buffer(), 0, termAtt.length());
                if (text.isEmpty()) {
                    return true;
                }
                parts = text.split("[^a-zA-Z0-9]");
                if (parts.length == 0) {
                    skipCounter += posIncrementAttribute.getPositionIncrement();
                } else {
                    if (skipCounter != 0) {
                        posIncrementAttribute.setPositionIncrement(posIncrementAttribute.getPositionIncrement() + skipCounter);
                    }
                    for (String part : parts) {
                        if (!part.isEmpty()) {
                            tokens.add(part);
                        }
                    }
                    break;
                }
            }
        }
        return addTerm();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void reset() throws IOException {
        super.reset();
        skipCounter = 0;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void end() throws IOException {
        super.end();
        posIncrementAttribute.setPositionIncrement(posIncrementAttribute.getPositionIncrement() + skipCounter);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(13, 103)
                .appendSuper(super.hashCode())
                .append(posIncrementAttribute)
                .append(skipCounter)
                .build();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof AlphaNumericFilter)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final AlphaNumericFilter rhs = (AlphaNumericFilter) obj;
        return new EqualsBuilder()
                .appendSuper(super.equals(obj))
                .append(skipCounter, rhs.skipCounter)
                .append(posIncrementAttribute, rhs.posIncrementAttribute)
                .isEquals();
    }
}
