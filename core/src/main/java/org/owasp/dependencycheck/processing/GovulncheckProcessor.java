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
package org.owasp.dependencycheck.processing;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;

import java.io.InputStream;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.Engine;
import static org.owasp.dependencycheck.analyzer.GolangVulncheckAnalyzer.DEPENDENCY_ECOSYSTEM;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.golang.GovulncheckJsonParser;
import org.owasp.dependencycheck.data.golang.GovulncheckResult;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.Reference;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.processing.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

/**
 * Processor for the output of <code>govulncheck -json</code>. For each
 * vulnerability reported it adds a synthetic dependency representing the
 * vulnerable Go module and attaches the vulnerability to it. When an alias
 * (CVE) is already known to dependency-check the existing vulnerability record
 * is reused so the finding de-duplicates against other data sources.
 *
 * @author Srinivas Chippagiri
 */
public class GovulncheckProcessor extends Processor<InputStream> {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(GovulncheckProcessor.class);
    /**
     * Reference to the dependency-check engine.
     */
    private final Engine engine;
    /**
     * Reference to the go.mod dependency that was scanned.
     */
    private final Dependency goDependency;
    /**
     * Temporary storage for an exception if it occurs during processing.
     */
    private AnalysisException analysisException;
    /**
     * Temporary storage for an exception if it occurs during processing.
     */
    private CpeValidationException cpeException;

    /**
     * Constructs a new processor to consume the output of `govulncheck`.
     *
     * @param goDependency a reference to the scanned `go.mod` dependency
     * @param engine a reference to the dependency-check engine
     */
    public GovulncheckProcessor(Dependency goDependency, Engine engine) {
        this.engine = engine;
        this.goDependency = goDependency;
    }

    @Override
    public void run() {
        try {
            final List<GovulncheckResult> results = GovulncheckJsonParser.process(getInput());
            for (GovulncheckResult result : results) {
                processResult(result);
            }
        } catch (AnalysisException ex) {
            this.analysisException = ex;
        } catch (CpeValidationException ex) {
            this.cpeException = ex;
        }
    }

    /**
     * Throws any exceptions that occurred during processing.
     *
     * @throws AnalysisException thrown if an analysis error occurred
     * @throws CpeValidationException thrown if a CPE validation error occurred
     */
    @Override
    public void close() throws AnalysisException, CpeValidationException {
        if (analysisException != null) {
            addSuppressedExceptions(analysisException, cpeException);
            throw analysisException;
        }
        if (cpeException != null) {
            throw cpeException;
        }
    }

    /**
     * Adds a dependency and vulnerability for a single govulncheck result.
     *
     * @param result the parsed govulncheck result
     * @throws CpeValidationException thrown if the vulnerable software cannot be
     * built
     */
    private void processResult(GovulncheckResult result) throws CpeValidationException {
        if (StringUtils.isBlank(result.getModuleName())) {
            LOGGER.debug("Skipping govulncheck result {} with no module information", result.getId());
            return;
        }
        final Dependency dependency = createDependency(result);
        final Vulnerability vulnerability = resolveVulnerability(result);
        dependency.addVulnerability(vulnerability);
        engine.addDependency(dependency);
    }

    /**
     * Resolves the vulnerability for a result, reusing an existing record from
     * the database when one of the aliases (typically a CVE) is already known,
     * otherwise synthesizing one from the govulncheck advisory.
     *
     * @param result the parsed govulncheck result
     * @return the vulnerability
     * @throws CpeValidationException thrown if the vulnerable software cannot be
     * built
     */
    private Vulnerability resolveVulnerability(GovulncheckResult result) throws CpeValidationException {
        final CveDB cvedb = engine.getDatabase();
        if (cvedb != null) {
            for (String alias : result.getAliases()) {
                if (alias != null && alias.startsWith("CVE-")) {
                    try {
                        final Vulnerability existing = cvedb.getVulnerability(alias);
                        if (existing != null) {
                            LOGGER.debug("Reusing {} from the database for govulncheck advisory {}", alias, result.getId());
                            return existing;
                        }
                    } catch (DatabaseException ex) {
                        LOGGER.debug("Unable to look up alias {} for govulncheck advisory {}", alias, result.getId());
                    }
                }
            }
        }
        return createVulnerability(result);
    }

    /**
     * Creates a synthetic dependency representing the vulnerable Go module.
     *
     * @param result the parsed govulncheck result
     * @return the dependency
     */
    private Dependency createDependency(GovulncheckResult result) {
        final String moduleName = result.getModuleName();
        final String version = result.getModuleVersion();
        final Dependency dep = new Dependency(goDependency.getActualFile(), true);

        final String identifier = StringUtils.isBlank(version) ? moduleName : moduleName + ":" + version;
        dep.setEcosystem(DEPENDENCY_ECOSYSTEM);
        dep.setDisplayFileName(identifier);
        dep.setName(moduleName);
        if (StringUtils.isNotBlank(version)) {
            dep.setVersion(version);
        }
        dep.setPackagePath(identifier);
        dep.setSha1sum(Checksum.getSHA1Checksum(identifier));
        dep.setMd5sum(Checksum.getMD5Checksum(identifier));
        dep.setSha256sum(Checksum.getSHA256Checksum(identifier));

        dep.addEvidence(EvidenceType.PRODUCT, "govulncheck", "module", moduleName, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.VENDOR, "govulncheck", "module", moduleName, Confidence.HIGH);
        if (StringUtils.isNotBlank(version)) {
            dep.addEvidence(EvidenceType.VERSION, "govulncheck", "version", version, Confidence.HIGHEST);
        }

        dep.addSoftwareIdentifier(buildPackageIdentifier(moduleName, version));
        return dep;
    }

    /**
     * Builds a Package-URL identifier for the given Go module, falling back to a
     * generic identifier when the purl cannot be built.
     *
     * @param moduleName the module path
     * @param version the module version
     * @return the software identifier
     */
    private org.owasp.dependencycheck.dependency.naming.Identifier buildPackageIdentifier(String moduleName, String version) {
        final PackageURLBuilder builder = PackageURLBuilder.aPackageURL().withType("golang");
        final int lastSlash = moduleName.lastIndexOf('/');
        if (lastSlash > 0) {
            builder.withNamespace(moduleName.substring(0, lastSlash));
            builder.withName(moduleName.substring(lastSlash + 1));
        } else {
            builder.withName(moduleName);
        }
        if (StringUtils.isNotBlank(version)) {
            builder.withVersion(version);
        }
        try {
            final PackageURL purl = builder.build();
            return new PurlIdentifier(purl, Confidence.HIGHEST);
        } catch (MalformedPackageURLException ex) {
            LOGGER.debug("Unable to build package url for go module {}", moduleName, ex);
            final StringBuilder value = new StringBuilder(moduleName);
            if (StringUtils.isNotBlank(version)) {
                value.append('@').append(version);
            }
            return new GenericIdentifier(value.toString(), Confidence.HIGHEST);
        }
    }

    /**
     * Synthesizes a vulnerability from a govulncheck advisory when no matching
     * record exists in the database.
     *
     * @param result the parsed govulncheck result
     * @return the vulnerability
     * @throws CpeValidationException thrown if the vulnerable software cannot be
     * built
     */
    private Vulnerability createVulnerability(GovulncheckResult result) throws CpeValidationException {
        final Vulnerability vulnerability = new Vulnerability();
        vulnerability.setSource(Vulnerability.Source.GOVULNCHECK);
        vulnerability.setName(result.getId());
        vulnerability.setUnscoredSeverity("UNKNOWN");
        vulnerability.setDescription(buildDescription(result));

        final String product = result.getModuleName();
        final VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();
        final VulnerableSoftware vs = builder.part(Part.APPLICATION)
                .vendor(String.format("%s_project", product))
                .product(product)
                .version(StringUtils.defaultIfBlank(result.getModuleVersion(), "*"))
                .build();
        vulnerability.addVulnerableSoftware(vs);
        vulnerability.setMatchedVulnerableSoftware(vs);

        for (String url : result.getReferences()) {
            final Reference ref = new Reference();
            ref.setName(result.getId());
            ref.setSource("govulncheck");
            ref.setUrl(url);
            vulnerability.addReference(ref);
        }
        return vulnerability;
    }

    /**
     * Builds a human-readable description for a synthesized vulnerability,
     * including reachability and remediation hints from govulncheck.
     *
     * @param result the parsed govulncheck result
     * @return the description
     */
    private String buildDescription(GovulncheckResult result) {
        final StringBuilder sb = new StringBuilder();
        if (StringUtils.isNotBlank(result.getSummary())) {
            sb.append(result.getSummary()).append("\n\n");
        }
        if (StringUtils.isNotBlank(result.getDetails())) {
            sb.append(result.getDetails()).append("\n\n");
        }
        if (result.isCalled()) {
            sb.append("Reachable: govulncheck determined a call to the vulnerable symbol `")
                    .append(result.getSymbol()).append("`.\n");
        } else {
            sb.append("Not reported as called: the vulnerable module is present but govulncheck did not "
                    + "observe a call into the vulnerable code.\n");
        }
        if (StringUtils.isNotBlank(result.getFixedVersion())) {
            sb.append("Fixed in version ").append(result.getFixedVersion()).append(".\n");
        }
        if (!result.getAliases().isEmpty()) {
            sb.append("Aliases: ").append(String.join(", ", result.getAliases())).append('.');
        }
        return sb.toString().trim();
    }
}
