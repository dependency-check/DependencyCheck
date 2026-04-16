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
 * Copyright (c) 2021 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.dependencycheck.utils.CvssUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Parser for npm audit v2 JSON output (auditReportVersion: 2).
 */
public class NpmAuditV2Parser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NpmAuditV2Parser.class);

    /**
     * Parses npm audit v2 JSON output into a list of advisories.
     *
     * @param v2Json    the npm audit v2 JSON object
     * @param directory the directory containing package-lock.json for version lookup
     * @return a list of advisories
     * @throws JSONException thrown if the JSON is not of the expected schema
     */
    public List<Advisory> parse(JSONObject v2Json, File directory) throws JSONException {
        final List<Advisory> advisories = new ArrayList<>();
        // Load package-lock.json packages for version lookup
        JSONObject packages = null;
        final File packageLockFile = new File(directory, "package-lock.json");
        if (packageLockFile.isFile()) {
            try {
                final String content = Files.readString(packageLockFile.toPath());
                packages = new JSONObject(content).optJSONObject("packages");
            } catch (IOException | JSONException e) {
                LOGGER.debug("Unable to read package-lock.json for version lookup: {}", e.getMessage());
            }
        }
        final JSONObject vulnerabilities = v2Json.optJSONObject("vulnerabilities");
        if (vulnerabilities == null) {
            return advisories;
        }
        final Iterator<String> keys = vulnerabilities.keys();
        while (keys.hasNext()) {
            final String packageName = keys.next();
            final JSONObject vuln = vulnerabilities.getJSONObject(packageName);
            final JSONArray via = vuln.optJSONArray("via");
            if (via == null || via.isEmpty()) {
                continue;
            }
            // Look up installed version from package-lock.json using the nodes path
            String installedVersion = null;
            if (packages != null) {
                final JSONArray nodes = vuln.optJSONArray("nodes");
                if (nodes != null && !nodes.isEmpty()) {
                    final String nodePath = nodes.optString(0, null);
                    if (nodePath != null) {
                        final JSONObject pkgEntry = packages.optJSONObject(nodePath);
                        if (pkgEntry != null) {
                            installedVersion = pkgEntry.optString("version", null);
                        }
                    }
                }
            }
            for (int i = 0; i < via.length(); i++) {
                processVia(via, i, packageName, vuln, installedVersion, advisories);
            }
        }
        return advisories;
    }

    private static void processVia(JSONArray via, int i, String packageName, JSONObject vuln, String installedVersion, List<Advisory> advisories) {
        final Object viaItem = via.get(i);
        if (!(viaItem instanceof JSONObject)) {
            return;
        }
        final JSONObject viaObj = (JSONObject) viaItem;
        final String url = viaObj.optString("url", null);
        if (url == null) {
            return;
        }
        final String ghsaId = extractGhsaId(url);
        if (ghsaId == null) {
            return;
        }
        final Advisory advisory = new Advisory();
        advisory.setGhsaId(ghsaId);
        advisory.setModuleName(packageName);
        advisory.setTitle(viaObj.optString("title", null));
        advisory.setSeverity(viaObj.optString("severity", vuln.optString("severity", null)));
        advisory.setVulnerableVersions(viaObj.optString("range", null));
        advisory.setOverview("URL: " + url);
        advisory.setReferences("- " + url);
        advisory.setVersion(installedVersion);
        NpmAuditParser.addCwesFromJsonToAdvisory(advisory, viaObj);
        advisory.setCves(new ArrayList<>());
        final JSONObject cvssData = viaObj.optJSONObject("cvss");
        if (cvssData != null) {
            final String vectorString = cvssData.optString("vectorString", null);
            if (vectorString != null && vectorString.startsWith("CVSS:3")) {
                try {
                    final double score = cvssData.optDouble("score", -1.0);
                    if (score >= 0) {
                        final CvssV3 cvss = CvssUtil.vectorToCvssV3(vectorString, score);
                        advisory.setCvssV3(cvss);
                    }
                } catch (IllegalArgumentException iae) {
                    LOGGER.warn("Invalid CVSS vector format in npm audit v2 results '{}': {}", vectorString, iae.getMessage());
                }
            }
        }
        advisories.add(advisory);
    }

    /**
     * Extracts the GHSA identifier from an advisory URL.
     * For example, {@code https://github.com/advisories/GHSA-34r7-q49f-h37c} returns
     * {@code GHSA-34r7-q49f-h37c}.
     *
     * @param url the advisory URL
     * @return the GHSA ID, or {@code null} if it cannot be extracted
     */
    public static String extractGhsaId(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        final int lastSlashIndex = url.lastIndexOf('/');
        if (lastSlashIndex == -1 || lastSlashIndex == url.length() - 1) {
            return null;
        }
        return url.substring(lastSlashIndex + 1);
    }
}
