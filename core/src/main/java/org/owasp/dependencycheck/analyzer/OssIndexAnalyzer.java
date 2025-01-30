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
 * Copyright (c) 2019 Jason Dillon. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import io.github.jeremylong.openvulnerability.client.nvd.CvssV2;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2Data;
import org.sonatype.ossindex.service.api.componentreport.ComponentReport;
import org.sonatype.ossindex.service.api.componentreport.ComponentReportVulnerability;
import org.sonatype.ossindex.service.api.cvss.Cvss2Severity;
import org.sonatype.ossindex.service.api.cvss.Cvss2Vector;
import org.sonatype.ossindex.service.api.cvss.CvssVector;
import org.sonatype.ossindex.service.api.cvss.CvssVectorFactory;
import org.sonatype.ossindex.service.client.OssindexClient;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.ossindex.OssindexClientFactory;

import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import org.sonatype.goodies.packageurl.PackageUrl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.net.SocketTimeoutException;

import javax.annotation.Nullable;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.utils.CvssUtil;
import org.sonatype.goodies.packageurl.InvalidException;
import org.sonatype.ossindex.service.client.transport.Transport.TransportException;

/**
 * Enrich dependency information from Sonatype OSS index.
 *
 * @author Jason Dillon
 * @since 5.0.0
 */
public class OssIndexAnalyzer extends AbstractAnalyzer {

    /**
     * A reference to the logger.
     */
    private static final Logger LOG = LoggerFactory.getLogger(OssIndexAnalyzer.class);

    /**
     * A pattern to match CVE identifiers.
     */
    private static final Pattern CVE_PATTERN = Pattern.compile("\\bCVE-\\d{4}-\\d{4,10}\\b");

    /**
     * The reference type.
     */
    public static final String REFERENCE_TYPE = "OSSINDEX";

    /**
     * Fetched reports.
     */
    private static Map<PackageUrl, ComponentReport> reports;

    /**
     * Lock to protect fetching state.
     */
    private static final Object FETCH_MUTIX = new Object();

    @Override
    public String getName() {
        return "Sonatype OSS Index Analyzer";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINDING_ANALYSIS_PHASE2;
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_OSSINDEX_ENABLED;
    }

    /**
     * Run without parallel support.
     *
     * @return false
     */
    @Override
    public boolean supportsParallelProcessing() {
        return true;
    }

    @Override
    protected void closeAnalyzer() throws Exception {
        synchronized (FETCH_MUTIX) {
            reports = null;
        }
    }

    @Override
    protected void analyzeDependency(final Dependency dependency, final Engine engine) throws AnalysisException {
        // batch request component-reports for all dependencies
        synchronized (FETCH_MUTIX) {
            if (reports == null) {
                try {
                    requestDelay();
                    reports = requestReports(engine.getDependencies());
                } catch (TransportException ex) {
                    final String message = ex.getMessage();
                    final boolean warnOnly = getSettings().getBoolean(Settings.KEYS.ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, false);
                    this.setEnabled(false);
                    if (StringUtils.endsWith(message, "401")) {
                        LOG.error("Invalid credentials for the OSS Index, disabling the analyzer");
                        throw new AnalysisException("Invalid credentials provided for OSS Index", ex);
                    } else if (StringUtils.endsWith(message, "403")) {
                        LOG.error("OSS Index access forbidden, disabling the analyzer");
                        throw new AnalysisException("OSS Index access forbidden", ex);
                    } else if (StringUtils.endsWith(message, "429")) {
                        if (warnOnly) {
                            LOG.warn("OSS Index rate limit exceeded, disabling the analyzer", ex);
                        } else {
                            throw new AnalysisException("OSS Index rate limit exceeded, disabling the analyzer", ex);
                        }
                    } else if (warnOnly) {
                        LOG.warn("Error requesting component reports, disabling the analyzer", ex);
                    } else {
                        LOG.debug("Error requesting component reports, disabling the analyzer", ex);
                        throw new AnalysisException("Failed to request component-reports", ex);
                    }
                } catch (SocketTimeoutException e) {
                    final boolean warnOnly = getSettings().getBoolean(Settings.KEYS.ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, false);
                    this.setEnabled(false);
                    if (warnOnly) {
                        LOG.warn("OSS Index socket timeout, disabling the analyzer", e);
                    } else {
                        LOG.debug("OSS Index socket timeout", e);
                        throw new AnalysisException("Failed to establish socket to OSS Index", e);
                    }
                } catch (Exception e) {
                    LOG.debug("Error requesting component reports", e);
                    throw new AnalysisException("Failed to request component-reports", e);
                }
            }

            // skip enrichment if we failed to fetch reports
            if (reports != null) {
                enrich(dependency);
            }
        }

    }

    /**
     * Delays each request (thread) by the configured amount of seconds, if the
     * configuration is present.
     */
    private void requestDelay() throws InterruptedException {
        final int delay = getSettings().getInt(Settings.KEYS.ANALYZER_OSSINDEX_REQUEST_DELAY, 0);
        if (delay > 0) {
            LOG.debug("Request delay: " + delay);
            TimeUnit.SECONDS.sleep(delay);
        }
    }

    /**
     * Helper to complain if unable to parse Package-URL.
     *
     * @param value the url to parse
     * @return the package url
     */
    @Nullable
    private PackageUrl parsePackageUrl(final String value) {
        try {
            return PackageUrl.parse(value);
        } catch (InvalidException e) {
            LOG.debug("Invalid Package-URL: {}", value, e);
            return null;
        }
    }

    /**
     * Batch request component-reports for all dependencies.
     *
     * @param dependencies the collection of dependencies
     * @return the map of dependency to OSS Index's component-report
     * @throws Exception thrown if there is an exception requesting the report
     */
    private Map<PackageUrl, ComponentReport> requestReports(final Dependency[] dependencies) throws Exception {
        LOG.debug("Requesting component-reports for {} dependencies", dependencies.length);
        // create requests for each dependency which has a PURL identifier
        final List<PackageUrl> packages = new ArrayList<>();
        Arrays.stream(dependencies).forEach(dependency -> dependency.getSoftwareIdentifiers().stream()
                .filter(id -> id instanceof PurlIdentifier)
                .map(id -> parsePackageUrl(id.getValue()))
                .filter(id -> id != null && StringUtils.isNotBlank(id.getVersion()))
                .forEach(packages::add));
        // only attempt if we have been able to collect some packages
        if (!packages.isEmpty()) {
            try (OssindexClient client = newOssIndexClient()) {
                LOG.debug("OSS Index Analyzer submitting: " + packages);
                return client.requestComponentReports(packages);
            }
        }
        LOG.warn("Unable to determine Package-URL identifiers for {} dependencies", dependencies.length);
        return Collections.emptyMap();
    }

    OssindexClient newOssIndexClient() {
        return OssindexClientFactory.create(getSettings());
    }

    /**
     * Attempt to enrich given dependency with vulnerability details from OSS
     * Index component-report.
     *
     * @param dependency the dependency to enrich
     */
    void enrich(final Dependency dependency) {
        LOG.debug("Enrich dependency: {}", dependency);

        for (Identifier id : dependency.getSoftwareIdentifiers()) {
            if (id instanceof PurlIdentifier) {
                LOG.debug("  Package: {} -> {}", id, id.getConfidence());

                final PackageUrl purl = parsePackageUrl(id.getValue());
                if (purl != null && StringUtils.isNotBlank(purl.getVersion())) {
                    try {
                        final ComponentReport report = reports.get(purl);
                        if (report == null) {
                            LOG.debug("Missing component-report for: " + purl);
                            continue;
                        }

                        // expose the URL to the package details for report generation
                        id.setUrl(report.getReference().toString());

                        report.getVulnerabilities().stream()
                                .map((vuln) -> transform(report, vuln))
                                .forEachOrdered((v) -> {
                                    final Vulnerability existing = dependency.getVulnerabilities().stream()
                                            .filter(e -> e.getName().equals(v.getName())).findFirst()
                                            .orElse(null);
                                    if (existing != null) {
                                        //TODO - can we enhance anything other than the references?
                                        existing.addReferences(v.getReferences());
                                    } else {
                                        dependency.addVulnerability(v);
                                    }
                                });
                    } catch (Exception e) {
                        LOG.warn("Failed to fetch component-report for: {}", purl, e);
                    }
                }
            }
        }
    }

    /**
     * Transform OSS Index component-report to ODC vulnerability.
     *
     * @param report the component report
     * @param source the vulnerability from the report to transform
     * @return the transformed vulnerability
     */
    private Vulnerability transform(final ComponentReport report, final ComponentReportVulnerability source) {
        final Vulnerability result = new Vulnerability();
        result.setSource(Vulnerability.Source.OSSINDEX);

        if (source.getCve() != null) {
            result.setName(source.getCve());
        } else {
            String cve = null;
            if (source.getTitle() != null) {
                final Matcher matcher = CVE_PATTERN.matcher(source.getTitle());
                if (matcher.find()) {
                    cve = matcher.group();
                } else {
                    cve = source.getTitle();
                }
            }
            if (cve == null && source.getReference() != null) {
                final Matcher matcher = CVE_PATTERN.matcher(source.getReference().toString());
                if (matcher.find()) {
                    cve = matcher.group();
                }
            }
            result.setName(cve != null ? cve : source.getId());
        }
        result.setDescription(source.getDescription());
        result.addCwe(source.getCwe());

        final double cvssScore = source.getCvssScore() != null ? source.getCvssScore().doubleValue() : -1;

        if (source.getCvssVector() != null) {
            if (source.getCvssVector().startsWith("CVSS:3")) {
                result.setCvssV3(CvssUtil.vectorToCvssV3(source.getCvssVector(), cvssScore));
            } else {
                // convert cvss details
                final CvssVector cvssVector = CvssVectorFactory.create(source.getCvssVector());
                final Map<String, String> metrics = cvssVector.getMetrics();
                if (cvssVector instanceof Cvss2Vector) {
                    String tmp = metrics.get(Cvss2Vector.ACCESS_VECTOR);
                    CvssV2Data.AccessVectorType accessVector = null;
                    if (tmp != null) {
                        accessVector = CvssV2Data.AccessVectorType.fromValue(tmp);
                    }
                    tmp = metrics.get(Cvss2Vector.ACCESS_COMPLEXITY);
                    CvssV2Data.AccessComplexityType accessComplexity = null;
                    if (tmp != null) {
                        accessComplexity = CvssV2Data.AccessComplexityType.fromValue(tmp);
                    }
                    tmp = metrics.get(Cvss2Vector.AUTHENTICATION);
                    CvssV2Data.AuthenticationType authentication = null;
                    if (tmp != null) {
                        authentication = CvssV2Data.AuthenticationType.fromValue(tmp);
                    }
                    tmp = metrics.get(Cvss2Vector.CONFIDENTIALITY_IMPACT);
                    CvssV2Data.CiaType confidentialityImpact = null;
                    if (tmp != null) {
                        confidentialityImpact = CvssV2Data.CiaType.fromValue(tmp);
                    }
                    tmp = metrics.get(Cvss2Vector.INTEGRITY_IMPACT);
                    CvssV2Data.CiaType integrityImpact = null;
                    if (tmp != null) {
                        integrityImpact = CvssV2Data.CiaType.fromValue(tmp);
                    }
                    tmp = metrics.get(Cvss2Vector.AVAILABILITY_IMPACT);
                    CvssV2Data.CiaType availabilityImpact = null;
                    if (tmp != null) {
                        availabilityImpact = CvssV2Data.CiaType.fromValue(tmp);
                    }
                    final String severity = Cvss2Severity.of((float) cvssScore).name().toUpperCase();
                    final CvssV2Data cvssData = new CvssV2Data("2.0", source.getCvssVector(), accessVector,
                            accessComplexity, authentication, confidentialityImpact,
                            integrityImpact, availabilityImpact, cvssScore,
                            severity, null, null, null, null, null, null, null, null, null, null);
                    final CvssV2 cvssV2 = new CvssV2(null, null, cvssData, severity, null, null, null, null, null, null, null);
                    result.setCvssV2(cvssV2);
                } else {
                    LOG.warn("Unsupported CVSS vector: {}", cvssVector);
                    result.setUnscoredSeverity(Double.toString(cvssScore));
                }
            }
        } else {
            LOG.debug("OSS has no vector for {}", result.getName());
            result.setUnscoredSeverity(Double.toString(cvssScore));
        }
        // generate a reference to the vulnerability details on OSS Index
        result.addReference(REFERENCE_TYPE, source.getTitle(), source.getReference().toString());

        // generate references to other references reported by OSS Index
        source.getExternalReferences().forEach(externalReference
                -> result.addReference("OSSIndex", externalReference.toString(), externalReference.toString()));

        // attach vulnerable software details as best we can
        final PackageUrl purl = report.getCoordinates();
        try {
            final VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder()
                    .part(Part.APPLICATION)
                    .vendor(purl.getNamespaceAsString())
                    .product(purl.getName())
                    .version(purl.getVersion());

            // TODO: consider if we want/need to extract version-ranges to apply to vulnerable-software?
            final VulnerableSoftware software = builder.build();
            result.addVulnerableSoftware(software);
            result.setMatchedVulnerableSoftware(software);
        } catch (CpeValidationException e) {
            LOG.warn("Unable to construct vulnerable-software for: {}", purl, e);
        }

        return result;
    }
}
