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
 * Copyright (c) 2026 OWASP dependency-check contributors. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.ruby;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2Data;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3Data;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4Data;
import org.apache.commons.lang3.Strings;
import org.jspecify.annotations.NonNull;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.utils.CvssUtil;

import java.io.IOException;
import java.io.Reader;
import java.time.LocalDate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Binds the JSON output of `bundle-audit check --format json` (bundle-audit
 * 0.8.0 or later) to {@link Report}.
 */
public final class BundleAuditJsonParser {

    /**
     * Reader for the bundle-audit report; unknown properties are ignored so
     * that newer bundle-audit releases do not break parsing.
     */
    private static final ObjectReader READER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .registerModule(new JavaTimeModule())
            .readerFor(Report.class);

    private BundleAuditJsonParser() {
    }

    /**
     * Parses a bundle-audit JSON report.
     *
     * @param reader the bundle-audit output
     * @return the report
     * @throws AnalysisException if the output is not a bundle-audit JSON report
     */
    public static Report parse(Reader reader) throws AnalysisException {
        final Report report;
        try {
            report = READER.readValue(reader);
        } catch (IOException ex) {
            throw new AnalysisException("Unable to parse the output of `bundle-audit check --format json`; "
                    + "bundler-audit 0.8.0 or later is required", ex);
        }
        if (report == null || report.results == null) {
            throw new AnalysisException("bundle-audit JSON report is missing the `results` array");
        }
        return report;
    }

    /**
     * The bundle-audit report: `{version, created_at, results[]}`.
     */
    public static final class Report {

        private final String version;
        private final List<GemResult> results;

        @JsonCreator
        private Report(@JsonProperty("version") String version,
                       @JsonProperty("results") List<GemResult> results) {
            this.version = version;
            this.results = results;
        }

        /**
         * @return the bundler-audit version that produced the report
         */
        public String getVersion() {
            return version;
        }

        public List<GemResult> getUnpatchedGems() {
            return results.stream()
                    .filter(GemResult::isUnpatchedGem)
                    .collect(Collectors.toUnmodifiableList());
        }
    }

    /**
     * A single result. Only `unpatched_gem` results (a gem plus an advisory)
     * are used; `insecure_source` results are ignored, as they were with the
     * text output.
     */
    public static final class GemResult {

        private final String type;
        private final Gem gem;
        private final Advisory advisory;

        @JsonCreator
        private GemResult(@JsonProperty("type") String type,
                          @JsonProperty("gem") Gem gem,
                          @JsonProperty("advisory") Advisory advisory) {
            this.type = type;
            this.gem = gem;
            this.advisory = advisory;
        }

        public Gem getGem() {
            return gem;
        }

        public Advisory getAdvisory() {
            return advisory;
        }

        public boolean isUnpatchedGem() {
            return "unpatched_gem".equals(type) && gem != null && advisory != null;
        }
    }

    /**
     * The affected gem.
     */
    public static final class Gem {

        private final String name;
        private final String version;

        @JsonCreator
        private Gem(@JsonProperty("name") String name,
                    @JsonProperty("version") String version) {
            this.name = name;
            this.version = version;
        }

        public String getName() {
            return name;
        }

        public String getVersion() {
            return version;
        }
    }

    /**
     * A ruby-advisory-db advisory as emitted by bundler-audit. The CVSS
     * entries are bare base scores (no vectors); `cvss_v4` is only emitted by
     * bundler-audit releases after 0.9.3. The CVE, GHSA and OSVDB identifiers
     * are emitted without their prefixes.
     */
    public static final class Advisory {

        /**
         * The source recorded on evidence and references created from the
         * bundle-audit output.
         */
        public static final String SOURCE = "bundle-audit";
        private final String id;
        private final String url;
        private final String title;
        private final LocalDate date;
        private final String description;
        private final Double cvssV2Score;
        private final Double cvssV3Score;
        private final Double cvssV4Score;
        private final String cveId;
        private final String osvdbId;
        private final String ghsaId;
        private final List<String> unaffectedVersions;
        private final List<String> patchedVersions;
        private final String criticality;

        //CSOFF: ParameterNumber
        @JsonCreator
        private Advisory(@JsonProperty("id") String id,
                         @JsonProperty("url") String url,
                         @JsonProperty("title") String title,
                         @JsonProperty("date") LocalDate date,
                         @JsonProperty("description") String description,
                         @JsonProperty("cvss_v2") Double cvssV2Score,
                         @JsonProperty("cvss_v3") Double cvssV3Score,
                         @JsonProperty("cvss_v4") Double cvssV4Score,
                         @JsonProperty("cve") String cveId,
                         @JsonProperty("osvdb") String osvdbId,
                         @JsonProperty("ghsa") String ghsaId,
                         @JsonProperty("unaffected_versions") List<String> unaffectedVersions,
                         @JsonProperty("patched_versions") List<String> patchedVersions,
                         @JsonProperty("criticality") String criticality) {
            this.id = id;
            this.url = url;
            this.title = title;
            this.date = date;
            this.description = description;
            this.cvssV2Score = cvssV2Score;
            this.cvssV3Score = cvssV3Score;
            this.cvssV4Score = cvssV4Score;
            this.cveId = Strings.CS.prependIfMissing(cveId, "CVE-");
            this.osvdbId = Strings.CS.prependIfMissing(osvdbId, "OSVDB-");
            this.ghsaId = Strings.CS.prependIfMissing(ghsaId, "GHSA-");
            this.unaffectedVersions = unaffectedVersions == null ? Collections.emptyList() : unaffectedVersions;
            this.patchedVersions = patchedVersions == null ? Collections.emptyList() : patchedVersions;
            this.criticality = criticality;
        }
        //CSON: ParameterNumber

        public String getId() {
            return id;
        }

        public String getUrl() {
            return url;
        }

        public String getTitle() {
            return title;
        }

        /**
         * @return the advisory disclosure date (an ISO-8601 calendar date)
         */
        public LocalDate getDate() {
            return date;
        }

        public String getDescription() {
            return description;
        }

        public Double getCvssV2Score() {
            return cvssV2Score;
        }

        public Double getCvssV3Score() {
            return cvssV3Score;
        }

        public Double getCvssV4Score() {
            return cvssV4Score;
        }

        public String getCveId() {
            return cveId;
        }

        public String getGhsaId() {
            return ghsaId;
        }

        public String getGhsaUrl() {
            return ghsaId == null ? null : "https://github.com/advisories/" + ghsaId;
        }

        public String getOsvdbId() {
            return osvdbId;
        }

        public List<String> getUnaffectedVersions() {
            return unaffectedVersions;
        }

        public List<String> getPatchedVersions() {
            return patchedVersions;
        }

        /**
         * @return the criticality label bundler-audit derived from the CVSS
         * scores (`none`, `low`, `medium`, `high`, `critical`), or null
         */
        public String getCriticality() {
            return criticality;
        }

        @NonNull
        public Optional<CvssV2> toCvssV2() {
            return Optional.ofNullable(getCvssV2Score())
                    .map(score -> {
                        final String severity = CvssUtil.cvssV2ScoreToSeverity(score);
                        // Need to use full constructor to set the severity right now, since it is immutable after the fact.
                        final CvssV2Data data = new CvssV2Data(CvssV2Data.Version._2_0, null, null, null, null, null, null, score, severity, null, null, null, null, null, null, null, null, null, null);
                        return new CvssV2(SOURCE, CvssV2.Type.SECONDARY, data, severity, null, null, null, null, null, null, null);
                    });
        }

        @NonNull
        public Optional<CvssV3> toCvssV3() {
            return Optional.ofNullable(getCvssV3Score())
                    .map(score -> new CvssV3(SOURCE, CvssV3.Type.SECONDARY, new CvssV3Data(CvssV3Data.Version._3_1, null, score, CvssUtil.cvssV3ScoreToSeverity(score))));
        }

        @NonNull
        public Optional<CvssV4> toCvssV4() {
            return Optional.ofNullable(getCvssV4Score())
                    .map(score -> new CvssV4(SOURCE, CvssV4.Type.SECONDARY, new CvssV4Data(CvssV4Data.Version._4_0, null, score, CvssUtil.cvssV4ScoreToSeverity(score))));
        }

        /**
         * Determines the name of the vulnerability: the CVE identifier when one
         * exists, otherwise the GHSA identifier, otherwise the legacy OSVDB
         * identifier, falling back to the advisory identifier from the
         * ruby-advisory-db.
         *
         * @return the vulnerability name
         */
        public String determineName() {
            return Optional.ofNullable(getCveId())
                    .or(() -> Optional.ofNullable(getGhsaId()))
                    .or(() -> Optional.ofNullable(getOsvdbId()))
                    .orElse(getId());
        }

        /**
         * Builds the vulnerability description from the advisory title, description and version information.
         *
         * @return the description
         */
        public String determineDescription() {
            final StringBuilder sb = new StringBuilder();

            Optional.ofNullable(getTitle()).ifPresent(title -> sb.append(title.trim()).append("\n\n"));
            Optional.ofNullable(getDescription()).ifPresent(description -> sb.append(description.trim()));

            if (!getPatchedVersions().isEmpty()) {
                sb.append("\n\nPatched versions: ").append(String.join(", ", getPatchedVersions()));
            }
            if (!getUnaffectedVersions().isEmpty()) {
                sb.append("\n\nUnaffected versions: ").append(String.join(", ", getUnaffectedVersions()));
            }
            return sb.toString();
        }
    }
}
