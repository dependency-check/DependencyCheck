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
package org.owasp.dependencycheck.data.nodeaudit;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.dependencycheck.utils.CvssUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Parser for the JSON output of `npm audit --json` (auditReportVersion 2, as
 * produced by npm 7 and later).
 *
 * <p>
 * The report contains a `vulnerabilities` object keyed by module name. Each
 * entry's `via` array holds either advisory objects (for modules that are the
 * direct subject of an advisory) or strings naming other vulnerable modules
 * (for modules that are only affected transitively). Only advisory objects are
 * converted into {@link Advisory} instances; transitive references would
 * otherwise duplicate the advisory of the module they point at.</p>
 */
public class NpmCliAuditParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NpmCliAuditParser.class);

    /**
     * Parses the JSON report from `npm audit --json`.
     *
     * @param report the JSON report to parse
     * @return a list of zero or more Advisory objects
     * @throws JSONException thrown if the JSON is not of the expected schema
     */
    public List<Advisory> parse(JSONObject report) throws JSONException {
        LOGGER.debug("Parsing npm audit report");
        final List<Advisory> advisories = new ArrayList<>();
        final JSONObject vulnerabilities = report.optJSONObject("vulnerabilities");
        if (vulnerabilities == null) {
            return advisories;
        }
        for (final String moduleName : vulnerabilities.keySet()) {
            final JSONObject vulnerability = vulnerabilities.getJSONObject(moduleName);
            final JSONArray via = vulnerability.optJSONArray("via");
            for (int i = 0; via != null && i < via.length(); i++) {
                final Object entry = via.get(i);
                if (entry instanceof JSONObject) {
                    advisories.add(parseAdvisory((JSONObject) entry));
                }
            }
        }
        return advisories;
    }

    /**
     * Parses a single advisory object from the `via` array of an npm audit
     * report entry.
     *
     * @param object the JSON object containing the advisory
     * @return the Advisory object
     * @throws JSONException thrown if the JSON is not of the expected schema
     */
    private Advisory parseAdvisory(JSONObject object) throws JSONException {
        final Advisory advisory = new Advisory();
        final String url = object.optString("url", null);
        final String title = object.optString("title", null);
        final String ghsaId = Advisory.ghsaIdFromUrl(url);
        if (ghsaId != null) {
            advisory.setGhsaId(ghsaId);
        } else {
            //fall back on the numeric GitHub Advisory Database identifier
            advisory.setGhsaId(object.optString("source", null));
        }
        advisory.setTitle(title);
        advisory.setOverview(title);
        if (url != null) {
            advisory.setReferences("- " + url);
        }
        advisory.setModuleName(object.optString("dependency", object.optString("name", null)));
        advisory.setSeverity(object.optString("severity", null));
        advisory.setVulnerableVersions(object.optString("range", null));

        final JSONArray jsonCwes = object.optJSONArray("cwe");
        final List<String> stringCwes = new ArrayList<>();
        if (jsonCwes != null) {
            for (int j = 0; j < jsonCwes.length(); j++) {
                stringCwes.add(jsonCwes.getString(j));
            }
        }
        advisory.setCwes(stringCwes);

        final JSONObject jsonCvss = object.optJSONObject("cvss");
        if (jsonCvss != null) {
            final double baseScore = jsonCvss.optDouble("score", -1.0);
            final String vector = jsonCvss.optString("vectorString", null);
if (baseScore >= 0.0 && vector != null && !"null".equals(vector)) {
                if (vector.startsWith("CVSS:3")) {
                    try {
                        final CvssV3 cvss = CvssUtil.vectorToCvssV3(vector, baseScore);
                        advisory.setCvssV3(cvss);
                    } catch (IllegalArgumentException iae) {
                        LOGGER.warn("Invalid CVSS vector format encountered in npm audit results '{}': {} ", vector, iae.getMessage());
                    }
                } else {
                    LOGGER.warn("Unsupported CVSS vector format in npm audit results, please file a feature "
                            + "request at https://github.com/dependency-check/DependencyCheck/issues/new/choose to "
                            + "support vector format '{}' ", vector);
                }
            }
        }
        return advisory;
    }
}
