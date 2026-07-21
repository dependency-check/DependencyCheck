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
 * Copyright (c) 2026 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.golang;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import jakarta.json.stream.JsonParsingException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.concurrent.ThreadSafe;

import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses the streaming JSON output of <code>govulncheck -json</code>.
 * <p>
 * govulncheck emits a stream of concatenated JSON objects, each wrapping a
 * single message keyed by its type (<code>config</code>, <code>SBOM</code>,
 * <code>progress</code>, <code>osv</code>, or <code>finding</code>); message
 * types other than {@code osv} and {@code finding} are ignored. The {@code osv} messages carry the
 * advisory metadata (id, aliases, description, references) while the
 * {@code finding} messages describe where a vulnerability was located, including
 * the module, version, and - when the vulnerable symbol is reachable - the
 * calling package and function.</p>
 * <p>
 * This parser joins the two: it produces one {@link GovulncheckResult} per
 * advisory, selecting the most precise finding for the advisory (a
 * &quot;called&quot; finding is preferred over a module-only one).</p>
 *
 * @author Srinivas Chippagiri
 */
@ThreadSafe
public final class GovulncheckJsonParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(GovulncheckJsonParser.class);

    private GovulncheckJsonParser() {
    }

    /**
     * Processes the govulncheck output stream into a list of results.
     *
     * @param inputStream the {@code govulncheck -json} output stream
     * @return the list of vulnerabilities found
     * @throws AnalysisException thrown if the output cannot be parsed
     */
    public static List<GovulncheckResult> process(InputStream inputStream) throws AnalysisException {
        LOGGER.debug("Beginning govulncheck output processing");

        final Map<String, JsonObject> advisories = new LinkedHashMap<>();
        // preserve advisory encounter order for a stable report
        final Map<String, JsonObject> bestFinding = new LinkedHashMap<>();

        // govulncheck emits a stream of indented JSON objects (json.MarshalIndent), one
        // message per object. Because string values never contain literal newlines, a line
        // that is exactly "}" marks the end of a top-level message, which lets us frame and
        // parse each message individually.
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            final StringBuilder current = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                current.append(line).append('\n');
                if ("}".equals(line)) {
                    handleMessage(current.toString(), advisories, bestFinding);
                    current.setLength(0);
                }
            }
        } catch (JsonParsingException jsonpe) {
            throw new AnalysisException("Error parsing output from `govulncheck -json`", jsonpe);
        } catch (JsonException | IllegalStateException | ClassCastException ex) {
            throw new AnalysisException("Error reading output from `govulncheck -json`", ex);
        } catch (IOException ex) {
            throw new AnalysisException("Error reading output of `govulncheck -json`", ex);
        }

        final List<GovulncheckResult> results = new ArrayList<>();
        for (Map.Entry<String, JsonObject> entry : bestFinding.entrySet()) {
            final JsonObject advisory = advisories.get(entry.getKey());
            results.add(buildResult(entry.getKey(), advisory, entry.getValue()));
        }
        return results;
    }

    /**
     * Parses a single framed govulncheck message and records its advisory or
     * finding.
     *
     * @param message the JSON text of a single message object
     * @param advisories the map of advisory id to OSV record
     * @param bestFinding the map of advisory id to the most precise finding
     */
    private static void handleMessage(String message, Map<String, JsonObject> advisories, Map<String, JsonObject> bestFinding) {
        try (JsonReader reader = Json.createReader(new StringReader(message))) {
            final JsonObject wrapper = reader.readObject();
            if (wrapper.containsKey("osv")) {
                final JsonObject osv = wrapper.getJsonObject("osv");
                final String id = osv.getString("id", null);
                if (id != null) {
                    advisories.put(id, osv);
                }
            } else if (wrapper.containsKey("finding")) {
                final JsonObject finding = wrapper.getJsonObject("finding");
                final String id = finding.getString("osv", null);
                if (id != null && isMorePrecise(finding, bestFinding.get(id))) {
                    bestFinding.put(id, finding);
                }
            }
        }
    }

    /**
     * Determines whether a newly seen finding is more precise than the one
     * currently retained for the advisory. A finding whose vulnerable frame
     * resolves a symbol (i.e. the vulnerability is reachable) is preferred over
     * one that only resolves a package or module.
     *
     * @param candidate the finding just parsed
     * @param current the finding currently retained (may be null)
     * @return <code>true</code> if the candidate should replace the current
     */
    private static boolean isMorePrecise(JsonObject candidate, JsonObject current) {
        if (current == null) {
            return true;
        }
        return precision(candidate) > precision(current);
    }

    /**
     * Scores the precision of a finding based on its most detailed trace frame:
     * 2 when a vulnerable symbol is resolved, 1 when a package is resolved, and
     * 0 when only the module is known.
     *
     * @param finding the finding to score
     * @return the precision score
     */
    private static int precision(JsonObject finding) {
        final JsonObject frame = vulnerableFrame(finding);
        if (frame == null) {
            return 0;
        }
        if (frame.getString("function", null) != null) {
            return 2;
        }
        if (frame.getString("package", null) != null) {
            return 1;
        }
        return 0;
    }

    /**
     * Returns the vulnerable frame for a finding - the first element of the
     * trace, which identifies the vulnerable module/package/symbol.
     *
     * @param finding the finding
     * @return the vulnerable frame, or null if the trace is empty
     */
    private static JsonObject vulnerableFrame(JsonObject finding) {
        final JsonArray trace = finding.getJsonArray("trace");
        if (trace == null || trace.isEmpty()) {
            return null;
        }
        return trace.getJsonObject(0);
    }

    /**
     * Builds a {@link GovulncheckResult} from an advisory record and its best
     * finding.
     *
     * @param id the advisory id
     * @param advisory the OSV advisory record (may be null if it was not seen)
     * @param finding the finding for the advisory
     * @return the assembled result
     */
    private static GovulncheckResult buildResult(String id, JsonObject advisory, JsonObject finding) {
        final JsonObject frame = vulnerableFrame(finding);
        final String moduleName = frame == null ? null : frame.getString("module", null);
        final String moduleVersion = frame == null ? null : frame.getString("version", null);
        final String packageName = frame == null ? null : frame.getString("package", null);
        final String symbol = frame == null ? null : frame.getString("function", null);
        final String fixedVersion = finding.getString("fixed_version", null);

        List<String> aliases = new ArrayList<>();
        List<String> references = new ArrayList<>();
        String summary = null;
        String details = null;
        if (advisory != null) {
            summary = advisory.getString("summary", null);
            details = advisory.getString("details", null);
            aliases = readStringArray(advisory, "aliases");
            references = readReferenceUrls(advisory);
        }
        return new GovulncheckResult(id, aliases, summary, details, references,
                moduleName, stripLeadingV(moduleVersion), stripLeadingV(fixedVersion), packageName, symbol);
    }

    /**
     * Reads a JSON array of strings from the given object.
     *
     * @param object the containing object
     * @param key the array key
     * @return the list of strings (never null)
     */
    private static List<String> readStringArray(JsonObject object, String key) {
        final List<String> values = new ArrayList<>();
        final JsonArray array = object.getJsonArray(key);
        if (array != null) {
            for (JsonString value : array.getValuesAs(JsonString.class)) {
                values.add(value.getString());
            }
        }
        return values;
    }

    /**
     * Reads the reference URLs from an OSV advisory's <code>references</code>
     * array.
     *
     * @param advisory the OSV advisory record
     * @return the list of reference URLs (never null)
     */
    private static List<String> readReferenceUrls(JsonObject advisory) {
        final List<String> urls = new ArrayList<>();
        final JsonArray references = advisory.getJsonArray("references");
        if (references != null) {
            for (JsonValue value : references) {
                if (value.getValueType() == JsonValue.ValueType.OBJECT) {
                    final String url = value.asJsonObject().getString("url", null);
                    if (url != null) {
                        urls.add(url);
                    }
                }
            }
        }
        return urls;
    }

    /**
     * Strips the leading <code>v</code> that Go module versions carry (e.g.
     * <code>v1.2.3</code> becomes <code>1.2.3</code>) so the version aligns with
     * the rest of dependency-check.
     *
     * @param version the raw version (may be null)
     * @return the normalized version, or null if the input was null
     */
    private static String stripLeadingV(String version) {
        if (version != null && version.startsWith("v")) {
            return version.substring(1);
        }
        return version;
    }
}
