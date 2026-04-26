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
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.NonNull;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.ossindex.OssIndexClientProvider;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.CvssUtil;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.Settings.KEYS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.goodies.packageurl.InvalidException;
import org.sonatype.goodies.packageurl.PackageUrl;
import org.sonatype.ossindex.service.api.componentreport.ComponentReport;
import org.sonatype.ossindex.service.api.componentreport.ComponentReportVulnerability;
import org.sonatype.ossindex.service.api.cvss.Cvss2Severity;
import org.sonatype.ossindex.service.api.cvss.Cvss2Vector;
import org.sonatype.ossindex.service.api.cvss.CvssVector;
import org.sonatype.ossindex.service.api.cvss.CvssVectorFactory;
import org.sonatype.ossindex.service.client.OssindexClient;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import javax.annotation.Nullable;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toList;
import static org.apache.hc.core5.http.HttpStatus.SC_FORBIDDEN;
import static org.apache.hc.core5.http.HttpStatus.SC_PAYMENT_REQUIRED;
import static org.apache.hc.core5.http.HttpStatus.SC_TOO_MANY_REQUESTS;
import static org.apache.hc.core5.http.HttpStatus.SC_UNAUTHORIZED;

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
    private static final Object FETCH_MUTEX = new Object();

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
        synchronized (FETCH_MUTEX) {
            reports = null;
        }
    }

    @Override
    protected void prepareAnalyzer(Engine engine) throws InitializationException {
        synchronized (FETCH_MUTEX) {
            if (getSettings().getString(KEYS.ANALYZER_OSSINDEX_URL, "").contains("ossindex.sonatype.org")) {
                LOG.warn("{} capabilities are being migrated to Sonatype Guide. All integrations must migrate to using " +
                        "a Sonatype Guide base URL or proxy. See " +
                        "https://dependency-check.github.io/DependencyCheck/analyzers/oss-index-analyzer.html " +
                        "for more information on migration to Sonatype Guide.", getName());
            }
            if (password().isEmpty() || (user().isEmpty() && passwordNotSonatypeGuideToken())) {
                LOG.warn("{} disabled due to missing credentials. Authentication with token is now required, and OSS Index " +
                        "is migrating to Sonatype Guide. See https://dependency-check.github.io/DependencyCheck/analyzers/oss-index-analyzer.html " +
                        "for more information on authentication with Sonatype Guide OSS Index.", getName());
                setEnabled(false);
            } else if (passwordNotSonatypeGuideToken()) {
                LOG.warn("Sonatype OSS Index is migrating to Sonatype Guide, but it looks like you're not yet using a Sonatype Guide personal " +
                        "access token. Legacy OSS Index API tokens should be replaced with Sonatype Guide Personal Access Tokens " +
                        "before December 31, 2026. See https://dependency-check.github.io/DependencyCheck/analyzers/oss-index-analyzer.html " +
                        "for more information on authentication with Sonatype Guide OSS Index.");
            }
        }
    }

    private boolean passwordNotSonatypeGuideToken() {
        return !password().startsWith("sonatype_pat_");
    }

    private @NonNull String user() {
        return getSettings().getString(KEYS.ANALYZER_OSSINDEX_USER, "");
    }

    private @NonNull String password() {
        return getSettings().getString(KEYS.ANALYZER_OSSINDEX_PASSWORD, "").trim();
    }

    @Override
    protected void analyzeDependency(final Dependency dependency, final Engine engine) throws AnalysisException {
        // batch request component-reports for all dependencies
        synchronized (FETCH_MUTEX) {
            if (reports == null && isEnabled()) {
                try {
                    requestDelay();
                    reports = requestReports(engine.getDependencies());
                } catch (SocketTimeoutException e) {
                    if (getSettings().getBoolean(KEYS.ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, false)) {
                        LOG.warn("Sonatype OSS Index / Guide socket timeout", e);
                    } else {
                        throw new AnalysisException("Failed to establish socket to Sonatype OSS Index / Guide", e);
                    }
                } catch (Exception ex) {
                    OssIndexKnownError error = Arrays.stream(OssIndexKnownError.values())
                            .filter(e -> e.matches(ex))
                            .findFirst()
                            .orElse(OssIndexKnownError.Unknown);

                    this.setEnabled(!error.fatal);
                    String logMessage = error.errorMessage(ex);

                    if (getSettings().getBoolean(KEYS.ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, false)) {
                        LOG.warn(logMessage);
                    } else {
                        throw new AnalysisException(logMessage, ex);
                    }
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
            LOG.debug("Request delay: {}", delay);
            sleepSeconds(delay);
        }
    }

    void sleepSeconds(int delay) throws InterruptedException {
        TimeUnit.SECONDS.sleep(delay);
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
        // create requests for each dependency which has a PURL identifier
        final List<PackageUrl> packages = Arrays.stream(dependencies)
                .flatMap(dependency -> dependency.getSoftwareIdentifiers().stream())
                .filter(id -> id instanceof PurlIdentifier)
                .map(id -> parsePackageUrl(id.getValue()))
                .filter(id -> id != null && StringUtils.isNotBlank(id.getVersion()))
                .distinct()
                .collect(toList());

        LOG.debug("Requesting component-reports for {} dependencies with {} unique Package-URL identifiers", dependencies.length, packages.size());
        // only attempt if we have been able to collect some packages
        if (!packages.isEmpty()) {
            try (OssindexClient client = OssIndexClientProvider.create(getSettings())) {
                LOG.debug("OSS Index Analyzer submitting: {}", packages);
                return client.requestComponentReports(packages);
            }
        }
        LOG.warn("Unable to determine Package-URL identifiers for {} dependencies", dependencies.length);
        return Collections.emptyMap();
    }

    /**
     * Known mappings of HTTP error codes to user messages
     */
    enum OssIndexKnownError {
        Unauthorized(SC_UNAUTHORIZED, "has invalid credentials", true),
        Forbidden(SC_FORBIDDEN, "access forbidden", true),
        TooManyRequests(SC_TOO_MANY_REQUESTS, "rate limit exceeded", false),
        InsufficientCredits(SC_PAYMENT_REQUIRED, "credits insufficient / payment required", true),
        Unknown(999, "had unknown error", false, Exception::getMessage);

        final int statusCode;
        final String userMessage;
        final boolean fatal;
        final Function<Exception, String> messageSuffix;

        OssIndexKnownError(int statusCode, String userMessage, boolean fatal) {
            this(statusCode, userMessage, fatal, ex -> "");
        }

        OssIndexKnownError(int statusCode, String userMessage, boolean fatal, Function<Exception, String> messageSuffix) {
            this.statusCode = statusCode;
            this.userMessage = userMessage;
            this.fatal = fatal;
            this.messageSuffix = messageSuffix;
        }

        private String errorMessage(Exception ex) {
            return String.format("Sonatype OSS Index / Guide %s%s. %s",
                    userMessage,
                    fatal ? ", disabling the analyzer" : "",
                    messageSuffix.apply(ex)
            ).trim();
        }

        private boolean matches(Exception ex) {
            return ex.toString().contains(Integer.toString(statusCode));
        }
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
                            LOG.debug("Missing component-report for: {}", purl);
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
        result.setName(nameFrom(source));
        result.setDescription(source.getDescription());
        result.addCwe(source.getCwe());

        final double cvssScore = source.getCvssScore() != null ? source.getCvssScore().doubleValue() : -1;

        if (source.getCvssVector() != null) {
            if (source.getCvssVector().startsWith("CVSS:4")) {
                result.setCvssV4(CvssUtil.vectorToCvssV4("ossindex", CvssV4.Type.PRIMARY, cvssScore, source.getCvssVector()));
            } else if (source.getCvssVector().startsWith("CVSS:3")) {
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
                    final CvssV2Data cvssData = new CvssV2Data(CvssV2Data.Version._2_0, source.getCvssVector(), accessVector,
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

    private static String nameFrom(ComponentReportVulnerability vuln) {
        return ofNullable(vuln.getCve())
                .or(() -> ofNullable(vuln.getTitle()).map(title -> matchesCveRegex(title)
                                .or(() -> ofNullable(vuln.getReference()).flatMap(reference -> matchesCveRegex(reference.toString())))
                                .orElse(title)))
                .orElse(vuln.getId());
    }

    private static Optional<String> matchesCveRegex(String value) {
        final Matcher matcher = CVE_PATTERN.matcher(value);
        if (matcher.find()) {
            return Optional.of(matcher.group());
        }
        return Optional.empty();
    }
}
