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
 * Copyright (c) 2026 Ben Sommerfeld. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import org.apache.commons.collections4.MultiValuedMap;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.semver4j.Semver;
import org.semver4j.SemverException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.owasp.dependencycheck.utils.CvssUtil;

/**
 * Parses the JSON response from {@code POST /-/npm/v1/security/advisories/bulk} and maps
 * advisories to installed versions using the dependency map from the lockfile.
 *
 * @see <a href="https://api-docs.npmjs.com/">npm Registry API</a>
 */
public class NpmBulkAuditParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NpmBulkAuditParser.class);

    /**
     * Parses the bulk advisory response into a flat advisory list with concrete version hits.
     *
     * @param bulkResponse top-level object: package name → array of advisory objects
     * @param dependencyMap module names to installed versions (from lockfile walk)
     * @return advisories for (module, version) pairs whose version satisfies {@code vulnerable_versions}
     * @throws JSONException if the response is malformed
     */
    public List<Advisory> parse(JSONObject bulkResponse, MultiValuedMap<String, String> dependencyMap)
            throws JSONException {
        final List<Advisory> out = new ArrayList<>();
        final Iterator<?> pkgKeys = bulkResponse.keys();
        while (pkgKeys.hasNext()) {
            final String moduleName = (String) pkgKeys.next();
            final JSONArray advisoriesForPkg = bulkResponse.optJSONArray(moduleName);
            if (advisoriesForPkg == null) {
                continue;
            }
            for (int i = 0; i < advisoriesForPkg.length(); i++) {
                final JSONObject raw = advisoriesForPkg.getJSONObject(i);
                for (String installedVersion : new LinkedHashSet<>(dependencyMap.get(moduleName))) {
                    final String normalized = NpmPayloadBuilder.normalizeVersion(installedVersion);
                    if (normalized == null || normalized.isEmpty()) {
                        continue;
                    }
                    final String range = raw.optString("vulnerable_versions", "");
                    if (range.isEmpty()) {
                        continue;
                    }
                    if (!versionSatisfiesRange(normalized, range)) {
                        continue;
                    }
                    out.add(toAdvisory(moduleName, normalized, raw));
                }
            }
        }
        return out;
    }

    private static boolean versionSatisfiesRange(String version, String range) {
        try {
            final Semver v = new Semver(version);
            return v.satisfies(range);
        } catch (SemverException ex) {
            LOGGER.debug("Skipping semver check for {} in range {}: {}", version, range, ex.getMessage());
            return false;
        }
    }

    private Advisory toAdvisory(String moduleName, String resolvedVersion, JSONObject object) throws JSONException {
        final Advisory advisory = new Advisory();
        if (object.has("github_advisory_id")) {
            advisory.setGhsaId(object.getString("github_advisory_id"));
        } else if (object.has("id")) {
            advisory.setGhsaId(String.valueOf(object.get("id")));
        }
        advisory.setOverview(object.optString("overview", null));
        advisory.setReferences(object.optString("references", null));
        advisory.setCreated(object.optString("created", null));
        advisory.setUpdated(object.optString("updated", null));
        advisory.setRecommendation(object.optString("recommendation", null));
        advisory.setTitle(object.optString("title", null));
        advisory.setModuleName(moduleName);
        advisory.setVersion(resolvedVersion);
        advisory.setVulnerableVersions(object.optString("vulnerable_versions", null));
        advisory.setPatchedVersions(object.optString("patched_versions", null));
        advisory.setAccess(object.optString("access", null));
        advisory.setSeverity(object.optString("severity", null));

        final JSONArray jsonCwes = object.optJSONArray("cwe");
        final List<String> stringCwes = new ArrayList<>();
        if (jsonCwes != null) {
            for (int j = 0; j < jsonCwes.length(); j++) {
                stringCwes.add(jsonCwes.getString(j));
            }
        }
        advisory.setCwes(stringCwes);

        final JSONArray jsonCves = object.optJSONArray("cves");
        final List<String> stringCves = new ArrayList<>();
        if (jsonCves != null) {
            for (int j = 0; j < jsonCves.length(); j++) {
                stringCves.add(jsonCves.getString(j));
            }
        }
        advisory.setCves(stringCves);

        final JSONObject jsonCvss = object.optJSONObject("cvss");
        if (jsonCvss != null) {
            final double baseScore = readNumericField(jsonCvss, "score", -1.0);
            if (baseScore >= 0.0) {
                final String vector = jsonCvss.isNull("vectorString") ? null : jsonCvss.optString("vectorString");
                if (vector != null && !vector.isEmpty() && !"null".equals(vector)) {
                    if (vector.startsWith("CVSS:3")) {
                        try {
                            final CvssV3 cvss = CvssUtil.vectorToCvssV3(vector, baseScore);
                            advisory.setCvssV3(cvss);
                        } catch (IllegalArgumentException iae) {
                            LOGGER.warn("Invalid CVSS vector format in NPM bulk audit '{}': {} ", vector, iae.getMessage());
                        }
                    } else {
                        LOGGER.warn("Unsupported CVSS vector format in NPM bulk audit results, please file a feature "
                                + "request at https://github.com/dependency-check/DependencyCheck/issues/new/choose to "
                                + "support vector format '{}' ", vector);
                    }
                }
            }
        }
        return advisory;
    }

    private static double readNumericField(JSONObject o, String key, double defaultValue) {
        if (!o.has(key) || o.isNull(key)) {
            return defaultValue;
        }
        final Object v = o.get(key);
        if (v instanceof Number) {
            return ((Number) v).doubleValue();
        }
        try {
            return Double.parseDouble(v.toString());
        } catch (NumberFormatException ex) {
            LOGGER.trace("Could not parse numeric field {}: {}", key, v);
            return defaultValue;
        }
    }
}
