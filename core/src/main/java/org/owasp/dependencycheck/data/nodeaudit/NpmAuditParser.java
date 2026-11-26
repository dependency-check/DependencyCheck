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
 * Copyright (c) 2018 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.dependencycheck.utils.CvssUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Parser for NPM Audit API response. This parser is derived from:
 * https://github.com/DependencyTrack/dependency-track/blob/master/src/main/java/org/owasp/dependencytrack/parser/npm/audit/NpmAuditParser.java
 *
 * @author Steve Springett
 */
public class NpmAuditParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NpmAuditParser.class);

    /**
     * Parses the JSON response from the NPM Audit API.
     *
     * @param jsonResponse the JSON node to parse
     * @return an AdvisoryResults object
     * @throws org.json.JSONException thrown if the JSON is not of the expected
     * schema
     */
    public List<Advisory> parse(JSONObject jsonResponse) throws JSONException {
        LOGGER.debug("Parsing JSON node");
        final List<Advisory> advisories = new ArrayList<>();
        final JSONObject jsonAdvisories = jsonResponse.getJSONObject("advisories");
        final Iterator<?> keys = jsonAdvisories.keys();
        while (keys.hasNext()) {
            final String key = (String) keys.next();
            advisories.addAll(parseAdvisory(jsonAdvisories.getJSONObject(key)));
        }
        return advisories;
    }

    /**
     * Parses an advisory from Node Audit or pnpm audit JSON, emitting one
     * {@link Advisory} per distinct version present in {@code findings} (or a
     * single {@link Advisory} with {@code version == null} if no version is
     * specified).
     *
     * @param object the JSON object containing the advisory
     * @return the list of parsed {@link Advisory} objects
     * @throws org.json.JSONException thrown if the JSON is not of the expected
     * schema
     */
    private List<Advisory> parseAdvisory(JSONObject object) throws JSONException {
        final List<String> stringCwes = parseCwes(object);
        final List<String> stringCves = parseCves(object);
        final CvssV3 cvssV3 = parseCvssV3(object);
        final Set<String> versions = parseFindingVersions(object);

        final List<Advisory> advisories = new ArrayList<>(versions.size());
        for (String version : versions) {
            final Advisory advisory = new Advisory();
            advisory.setGhsaId(object.getString("github_advisory_id"));
            advisory.setOverview(object.optString("overview", null));
            advisory.setReferences(object.optString("references", null));
            advisory.setCreated(object.optString("created", null));
            advisory.setUpdated(object.optString("updated", null));
            advisory.setRecommendation(object.optString("recommendation", null));
            advisory.setTitle(object.optString("title", null));
            advisory.setModuleName(object.optString("module_name", null));
            advisory.setVulnerableVersions(object.optString("vulnerable_versions", null));
            advisory.setPatchedVersions(object.optString("patched_versions", null));
            advisory.setAccess(object.optString("access", null));
            advisory.setSeverity(object.optString("severity", null));
            advisory.setCwes(stringCwes);
            advisory.setVersion(version);
            if (stringCves != null) {
                advisory.setCves(stringCves);
            }
            if (cvssV3 != null) {
                advisory.setCvssV3(cvssV3);
            }
            advisories.add(advisory);
        }
        return advisories;
    }

    /**
     * Extracts CWE identifiers from the advisory JSON, supporting both array
     * and scalar string representations.
     *
     * @param object the advisory JSON object
     * @return list of CWE strings
     */
    private List<String> parseCwes(JSONObject object) {
        final JSONArray jsonCwes = object.optJSONArray("cwe");
        final List<String> stringCwes = new ArrayList<>();
        if (jsonCwes != null) {
            for (int j = 0; j < jsonCwes.length(); j++) {
                stringCwes.add(jsonCwes.getString(j));
            }
        } else {
            final String cwe = object.optString("cwe", null);
            if (cwe != null && !cwe.isEmpty()) {
                stringCwes.add(cwe);
            }
        }
        return stringCwes;
    }

    /**
     * Extracts CVE identifiers from the advisory JSON.
     *
     * @param object the advisory JSON object
     * @return list of CVE strings, or {@code null} if {@code cves} is absent
     */
    private List<String> parseCves(JSONObject object) {
        final JSONArray jsonCves = object.optJSONArray("cves");
        if (jsonCves == null) {
            return null;
        }
        final List<String> stringCves = new ArrayList<>();
        for (int j = 0; j < jsonCves.length(); j++) {
            stringCves.add(jsonCves.getString(j));
        }
        return stringCves;
    }

    /**
     * Extracts distinct affected package versions from {@code findings}.
     *
     * @param object the advisory JSON object
     * @return non-empty set of versions (containing {@code null} if no versions
     * were present in {@code findings})
     */
    private Set<String> parseFindingVersions(JSONObject object) {
        final Set<String> versions = new LinkedHashSet<>();
        final JSONArray findings = object.optJSONArray("findings");
        if (findings != null) {
            for (int i = 0; i < findings.length(); i++) {
                final JSONObject finding = findings.optJSONObject(i);
                if (finding != null) {
                    final String version = finding.optString("version", null);
                    if (version != null && !version.isEmpty()) {
                        versions.add(version);
                    }
                }
            }
        }
        if (versions.isEmpty()) {
            versions.add(null);
        }
        return versions;
    }

    /**
     * Extracts CVSSv3 metadata from the advisory JSON when available.
     *
     * @param object the advisory JSON object
     * @return parsed {@link CvssV3} or {@code null}
     */
    private CvssV3 parseCvssV3(JSONObject object) {
        final JSONObject jsonCvss = object.optJSONObject("cvss");
        if (jsonCvss != null) {
            double baseScore = -1.0;
            final String score = jsonCvss.optString("score");
            if (score != null) {
                try {
                    baseScore = Float.parseFloat(score);
                } catch (NumberFormatException ignored) {
                    LOGGER.trace("Swallowed NumberFormatException", ignored);
                    baseScore = -1.0f;
                }
            }
            if (baseScore >= 0.0) {
                final String vector = jsonCvss.optString("vectorString");
                if (vector != null && !"null".equals(vector)) {
                    if (vector.startsWith("CVSS:3")) {
                        try {
                            return CvssUtil.vectorToCvssV3(vector, baseScore);
                        } catch (IllegalArgumentException iae) {
                            LOGGER.warn("Invalid CVSS vector format encountered in NPM Audit results '{}': {} ", vector, iae.getMessage());
                        }
                    } else {
                        LOGGER.warn("Unsupported CVSS vector format in NPM Audit results, please file a feature "
                                + "request at https://github.com/dependency-check/DependencyCheck/issues/new/choose to "
                                + "support vector format '{}' ", vector);
                    }
                }
            }
        }
        return null;
    }
}
