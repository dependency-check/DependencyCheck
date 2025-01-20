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
 * Copyright (c) 2015 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.golang;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.concurrent.ThreadSafe;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonReaderFactory;
import jakarta.json.stream.JsonParsingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.utils.JsonArrayFixingInputStream;

/**
 * Parses json output from `go list -json -m all`.
 *
 * @author Matthijs van den Bos
 */
@ThreadSafe
public final class GoModJsonParser {

    /**
     * The LOGGER
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(GoModJsonParser.class);

    private GoModJsonParser() {
    }

    /**
     * Process the input stream to create the list of dependencies.
     *
     * @param inputStream the InputStream to parse
     * @return the list of dependencies
     * @throws AnalysisException thrown when there is an error parsing the
     * results of `go mod`
     */
    public static List<GoModDependency> process(InputStream inputStream) throws AnalysisException {
        LOGGER.debug("Beginning go.mod processing");

        final List<GoModDependency> goModDependencies = new ArrayList<>();
        try (JsonArrayFixingInputStream jsonStream = new JsonArrayFixingInputStream(inputStream)) {
            final JsonReaderFactory factory = Json.createReaderFactory(null);
            try (JsonReader reader = factory.createReader(jsonStream, java.nio.charset.StandardCharsets.UTF_8)) {
                final JsonArray modules = reader.readArray();
                modules.getValuesAs(JsonObject.class).forEach((module) -> {
                    final String path = module.getString("Path");
                    String version = module.getString("Version", null);
                    if (version != null && version.startsWith("v")) {
                        version = version.substring(1);
                    }
                    String dir = null;
                    if (module.getJsonString("Dir") != null) {
                        dir = module.getString("Dir");
                    }
                    goModDependencies.add(new GoModDependency(path, version, dir));
                });
            }
        } catch (JsonParsingException jsonpe) {
            throw new AnalysisException("Error parsing output from `go list -json -m all`", jsonpe);
        } catch (JsonException jsone) {
            throw new AnalysisException("Error reading output from `go list -json -m all`", jsone);
        } catch (IllegalStateException ise) {
            throw new AnalysisException("Illegal state in go mod stream", ise);
        } catch (ClassCastException cce) {
            throw new AnalysisException("JSON not exactly matching output of `go list -json -m all`", cce);
        } catch (IOException ex) {
            throw new AnalysisException("Error reading output of `go list -json -m all`", ex);
        }
        return goModDependencies;
    }
}
