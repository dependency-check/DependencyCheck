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
 * Copyright (c) 2020 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.elixir;

import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.NotThreadSafe;

import jakarta.json.stream.JsonParsingException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;

/**
 * Parses json output from `mix_audit --format json`.
 *
 * @author Christoph Sassenberg
 */
@NotThreadSafe
public class MixAuditJsonParser {

    /**
     * A key in the mix json file.
     */
    static final String PASS_FAIL_KEY = "pass";
    /**
     * A key in the mix json file.
     */
    static final String RESULTS_KEY = "vulnerabilities";
    /**
     * A key in the mix json file.
     */
    static final String ADVISORY_KEY = "advisory";
    /**
     * A key in the mix json file.
     */
    static final String DEPENDENCY_KEY = "dependency";

    /**
     * The JsonReader for parsing JSON.
     */
    private final JsonReader jsonReader;

    /**
     * The List of MixAuditResults found.
     */
    private final List<MixAuditResult> mixAuditResults;

    /**
     * Whether the mix audit passed or failed.
     */
    private boolean mixAuditPass;

    /**
     * The LOGGER
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(MixAuditJsonParser.class);

    /**
     * Creates a MixAuditJsonParser from a Reader.
     *
     * @param reader - the java.io.Reader to read the json character stream from
     */
    public MixAuditJsonParser(Reader reader) {
        LOGGER.debug("Creating a MixAuditJsonParser");
        this.jsonReader = Json.createReader(reader);
        this.mixAuditResults = new ArrayList<>();
        this.mixAuditPass = false;
    }

    /**
     * Process the input stream to create the list of dependencies.
     *
     * @throws AnalysisException thrown when there is an error parsing the
     * results of `mix_audit --format json`
     */
    public void process() throws AnalysisException {
        LOGGER.debug("Beginning mix_audit json output processing");
        try {
            final JsonObject output = jsonReader.readObject();
            if (output.containsKey(PASS_FAIL_KEY)) {
                this.mixAuditPass = output.getBoolean(PASS_FAIL_KEY);
            }

            if (output.containsKey(RESULTS_KEY) && output.isNull(RESULTS_KEY)) {
                LOGGER.debug("Found vulnerabilities");
            }
            final JsonArray results = output.getJsonArray(RESULTS_KEY);
            for (JsonObject result : results.getValuesAs(JsonObject.class)) {
                final JsonObject advisory = result.getJsonObject(ADVISORY_KEY);
                final JsonObject dependency = result.getJsonObject(DEPENDENCY_KEY);
                final ArrayList<String> patchedVersions = new ArrayList<>();

                for (JsonString patchedVersion : advisory.getJsonArray("patched_versions").getValuesAs(JsonString.class)) {
                    patchedVersions.add(patchedVersion.getString());
                }

                final MixAuditResult r = new MixAuditResult(
                        advisory.getString("id"),
                        advisory.getString("cve"),
                        advisory.getString("title"),
                        advisory.getString("description"),
                        advisory.getString("disclosure_date"),
                        advisory.getString("url"),
                        patchedVersions,
                        dependency.getString("lockfile"),
                        dependency.getString("package"),
                        dependency.getString("version")
                );

                this.mixAuditResults.add(r);
            }
        } catch (JsonParsingException jsonpe) {
            throw new AnalysisException("Error parsing stream", jsonpe);
        } catch (JsonException jsone) {
            throw new AnalysisException("Error reading stream", jsone);
        } catch (IllegalStateException ise) {
            throw new AnalysisException("Illegal state while parsing mix_audit output", ise);
        } catch (ClassCastException cce) {
            throw new AnalysisException("JSON not exactly matching output of `mix_audit --format json`", cce);
        }
    }

    /**
     * Gets the list of results.
     *
     * @return the list of results
     */
    public List<MixAuditResult> getResults() {
        return mixAuditResults;
    }
}
