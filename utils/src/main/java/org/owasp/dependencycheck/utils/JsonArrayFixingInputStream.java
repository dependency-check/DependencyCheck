/*
 * This file is part of dependency-check-utils.
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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.IOException;
import java.io.InputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fixes a poorly formatted jSON array such as those returned by
 * <code>go list -json -m all</code>.
 * <p>
 * Example:</p>
 * <code>
 * { "name1": "value" }
 * { "name2" : "value" }
 * </code> Would be transformed into:  <code>
 * [{ "name1": "value" },
 * { "name2" : "value" }]
 * </code>
 * <p>
 * Note that this is a naive implementation and will incorrectly transform a
 * stream if there are '}' contained within the names of values.</p>
 *
 * @author Jeremy Long
 */
public class JsonArrayFixingInputStream extends InputStream {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(JsonArrayFixingInputStream.class);
    /**
     * The buffer length.
     */
    private static final int BUFFER_SIZE = 2048;
    /**
     * The input stream to be filtered.
     */
    private final InputStream in;
    /**
     * The read buffer.
     */
    private final byte[] buffer = new byte[BUFFER_SIZE];
    /**
     * The read offset for the buffer.
     */
    private int bufferStart = 0;
    /**
     * The number characters available to read.
     */
    private int bufferAvailable = 0;
    /**
     * A flag indicating if the output still requires a trailing curly brace.
     */
    private boolean needsTrailingBrace = true;
    /**
     * A flag indicating if the stream is just starting.
     */
    private boolean firstRead = true;

    /**
     * Constructs a new filtering input stream used to fix a poorly formatted
     * JSON array.
     *
     * @param in the InputStream containing the poorly formed JSON array
     */
    public JsonArrayFixingInputStream(InputStream in) {
        this.in = in;
        this.bufferAvailable = 1;
        buffer[bufferStart] = '[';
    }

    /**
     * Advances the buffer to the next block if required.
     *
     * @return the number of characters read
     * @throws IOException thrown if there is an error reading from the stream
     */
    private boolean advanceStream() throws IOException {
        boolean chomp = false;
        if (firstRead) {
            chomp = true;
            firstRead = false;
            bufferStart = 0;
            bufferAvailable = in.read(buffer, 1, BUFFER_SIZE - 1) + 1;
        } else if (bufferAvailable == 0) {
            chomp = true;
            bufferStart = 0;
            bufferAvailable = in.read(buffer, 0, BUFFER_SIZE);
        }
        if (chomp) {
            //chomp new lines
            while (bufferAvailable > 0
                    && (buffer[bufferStart + bufferAvailable - 1] == '\n'
                    || buffer[bufferStart + bufferAvailable - 1] == '\r')) {
                bufferAvailable -= 1;
            }
            if (bufferAvailable == 0) {
                return advanceStream();
            }
        }
        return bufferAvailable > 0;
    }

    //CSOFF: NestedIfDepth
    /**
     * Increments the buffer start and appropriately inserts any necessary
     * needed curly braces or commas.
     *
     * @throws IOException thrown if there is an error reading from the stream
     */
    private void incrementRead() throws IOException {
        // buffer[bufferStart] is the value that was just read.
        if (buffer[bufferStart] == '}') {
            if (bufferAvailable > 1) {
                if (hasTrailingComma(bufferStart)) {
                    //increment normally
                    bufferStart += 1;
                    bufferAvailable -= 1;
                } else {
                    //replace '}' with ',' and don't increment counters
                    buffer[bufferStart] = ',';
                }
            } else {
                bufferAvailable = 0;
                if (advanceStream() || needsTrailingBrace) {
                    if (bufferAvailable >= 1) {
                        //the stream was advanced - so check if buffer[0] has a comma
                        if (!hasTrailingComma(-1)) {
                            //this only works because the output always
                            // has a \n following a closing/open brace...
                            if (buffer[bufferStart] == 10 || buffer[bufferStart] == 13) {
                                buffer[bufferStart] = ',';
                            } else if (buffer[bufferStart] == '{'
                                    && (buffer[bufferStart + 1] == 10 || buffer[bufferStart + 1] == 13)) {
                                buffer[bufferStart] = ',';
                                buffer[bufferStart + 1] = '{';
                            }
                        }
                    } else if (needsTrailingBrace) {
                        needsTrailingBrace = false;
                        buffer[bufferStart] = ']';
                        bufferAvailable = 1;
                    }
                }
            }
        } else {
            bufferStart += 1;
            bufferAvailable -= 1;
        }
    }
    //CSON: NestedIfDepth

    /**
     * Searches for the offset from the buffer start for the next closing curly
     * brace.
     *
     * @return the offset if found; otherwise <code>-1</code>
     */
    private int getClosingBraceOffset() {
        for (int pos = bufferStart; pos < BUFFER_SIZE && pos < (bufferStart + bufferAvailable); pos++) {
            if (buffer[pos] == '}') {
                return pos - bufferStart;
            }
        }
        return -1;
    }

    @Override
    public int read() throws IOException {
        if (advanceStream()) {
            final int value = buffer[bufferStart];
            incrementRead();
            return value;
        }
        return -1;
    }

    @Override
    public int read(byte[] b) throws IOException {
        return this.read(b, 0, b.length);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (advanceStream()) {
            final int brace = getClosingBraceOffset();
            if (brace == 0) {
                b[off] = buffer[bufferStart];
                incrementRead();
                return 1;
            }
            int copyLength = Math.min(bufferAvailable, len);
            if (brace > 0) {
                copyLength = Math.min(copyLength, brace);
            }
            final int copyEnd = copyLength + off;
            for (int pos = off; pos < copyEnd; pos++) {
                b[pos] = buffer[bufferStart];
                bufferStart += 1;
            }
            bufferAvailable -= copyLength;
            return copyLength;
        }
        return -1;
    }

    @Override
    public long skip(long n) throws IOException {
        throw new UnsupportedOperationException("Unable to skip using the JsonArrayFixingInputStream");
    }

    @Override
    public int available() throws IOException {
        return in.available() + bufferAvailable;
    }

    @Override
    public void close() throws IOException {
        if (in != null) {
            in.close();
        }
    }

    /**
     * Tests if the buffer has a trailing comma after having just output a
     * closing curly brace.
     *
     * @param start the position to start checking the buffer from
     * @return <code>true</code> if there is a trailing comma; otherwise
     * <code>false</code>
     */
    private boolean hasTrailingComma(int start) {
        return (bufferAvailable >= 1 && buffer[start + 1] == ',')
                || bufferAvailable >= 2 && isWhiteSpace(buffer[start + 1]) && buffer[start + 2] == ',';
    }

    /**
     * Tests if the byte passed in is a white space character.
     *
     * @param c the byte representing the character to test
     * @return <code>true</code> if the byte is white space; otherwise
     * <code>false</code>
     */
    protected boolean isWhiteSpace(byte c) {
        switch (c) {
            case '\n':
            case '\r':
            case '\t':
            case ' ':
                return true;
            default:
                return false;
        }
    }
}
