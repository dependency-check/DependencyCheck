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
package org.owasp.dependencycheck.data.update.nvd.api;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;

public class CveApiJson20CveItemSource implements CveItemSource<DefCveItem> {

    /**
     * The object mapper.
     */
    private final ObjectMapper mapper;
    /**
     * The input stream.
     */
    private final InputStream inputStream;
    /**
     * The JSON Parser
     */
    private final JsonParser jsonParser;
    /**
     * The current item.
     */
    private DefCveItem currentItem;
    /**
     * The next item.
     */
    private DefCveItem nextItem;

    /**
     * Constructs a CVE Item Source record.
     *
     * @param inputStream the input source to read from
     * @throws IOException thrown if there is an issue reading from the input
     * stream
     */
    public CveApiJson20CveItemSource(InputStream inputStream) throws IOException {
        mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        this.inputStream = inputStream;
        jsonParser = mapper.getFactory().createParser(inputStream);

        JsonToken token = null;
        do {
            token = jsonParser.nextToken();
            if (token == JsonToken.FIELD_NAME) {
                final String fieldName = jsonParser.currentName();
                if ("vulnerabilities".equals(fieldName) && (jsonParser.nextToken() == JsonToken.START_ARRAY)) {
                    nextItem = readItem(jsonParser);
                }
            }
        } while (token != null && nextItem == null);
    }

    @Override
    public void close() throws Exception {
        IOUtils.closeQuietly(jsonParser, inputStream);
    }

    @Override
    public boolean hasNext() {
        return nextItem != null;
    }

    @Override
    public DefCveItem next() throws IOException {
        currentItem = nextItem;
        nextItem = readItem(jsonParser);
        return currentItem;
    }

    private DefCveItem readItem(JsonParser jsonParser) throws IOException {
        if (jsonParser.nextToken() == JsonToken.START_OBJECT) {
            return mapper.readValue(jsonParser, DefCveItem.class);
        }
        return null;
    }
}
