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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.processing;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import org.owasp.dependencycheck.Engine;
import static org.owasp.dependencycheck.analyzer.ElixirMixAuditAnalyzer.DEPENDENCY_ECOSYSTEM;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.elixir.MixAuditJsonParser;
import org.owasp.dependencycheck.data.elixir.MixAuditResult;
import org.owasp.dependencycheck.dependency.Confidence;

import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
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
 * Processor for the output of `mix_audit`.
 *
 * @author Jeremy Long
 */
public class MixAuditProcessor extends Processor<InputStream> {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(MixAuditProcessor.class);
    /**
     * Reference to the dependency-check engine.
     */
    private final Engine engine;
    /**
     * Reference to the go.mod dependency.
     */
    private final Dependency mixDependency;
    /**
     * Temporary storage for an exception if it occurs during the processing.
     */
    private IOException ioException;
    /**
     * Temporary storage for an exception if it occurs during the processing.
     */
    private CpeValidationException cpeException;
    /**
     * Temporary storage for an exception if it occurs during the processing.
     */
    private AnalysisException analysisException;

    /**
     * Constructs a new processor to consume the output of `mix_audit`.
     *
     * @param mixDependency a reference to `mix.lock` dependency
     * @param engine a reference to the dependency-check engine
     */
    public MixAuditProcessor(Dependency mixDependency, Engine engine) {
        this.engine = engine;
        this.mixDependency = mixDependency;
    }

    @Override
    public void run() {
        try (BufferedReader rdr = new BufferedReader(new InputStreamReader(getInput(), StandardCharsets.UTF_8))) {
            processMixAuditOutput(rdr);
        } catch (IOException ex) {
            this.ioException = ex;
        } catch (AnalysisException ex) {
            this.analysisException = ex;
        } catch (CpeValidationException ex) {
            this.cpeException = ex;
        }
    }

    /**
     * Throws any exceptions that occurred during processing.
     *
     * @throws IOException thrown if there was an error reading from the process
     * @throws AnalysisException thrown if an analysis error occurred
     * @throws CpeValidationException if there is an error building the
     * CPE/VulnerableSoftware object
     */
    @Override
    public void close() throws IOException, AnalysisException, CpeValidationException {
        if (ioException != null) {
            addSuppressedExceptions(ioException, analysisException, cpeException);
            throw ioException;
        }
        if (analysisException != null) {
            addSuppressedExceptions(analysisException, cpeException);
            throw analysisException;
        }
        if (cpeException != null) {
            throw cpeException;
        }
    }

    /**
     * Processes the mix audit output.
     *
     * @param rdr the reader of the report
     * @throws AnalysisException thrown if an analysis error occurred
     * @throws CpeValidationException if there is an error building the
     * CPE/VulnerableSoftware object
     */
    private void processMixAuditOutput(BufferedReader rdr) throws AnalysisException, CpeValidationException {
        final MixAuditJsonParser parser = new MixAuditJsonParser(rdr);
        parser.process();

        for (MixAuditResult result : parser.getResults()) {
            final Dependency dependency = createDependency(mixDependency, result.getDependencyPackage(), result.getDependencyVersion());
            Vulnerability vulnerability = engine.getDatabase().getVulnerability(result.getCve());

            if (vulnerability == null) {
                vulnerability = createVulnerability(result);
            }

            dependency.addVulnerability(vulnerability);
            engine.addDependency(dependency);
        }
    }

    private Dependency createDependency(Dependency parentDependency, String packageName, String version) {
        final Dependency dep = new Dependency(parentDependency.getActualFile(), true);

        final String identifier = String.format("%s:%s", packageName, version);

        dep.setEcosystem(DEPENDENCY_ECOSYSTEM);
        dep.setDisplayFileName(identifier);
        dep.setName(packageName);
        dep.setVersion(version);
        dep.setPackagePath(identifier);
        dep.setMd5sum(Checksum.getMD5Checksum(identifier));
        dep.setSha1sum(Checksum.getSHA1Checksum(identifier));
        dep.setSha256sum(Checksum.getSHA256Checksum(identifier));

        dep.addEvidence(EvidenceType.VERSION, "mix_audit", "Version", version, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.PRODUCT, "mix_audit", "Package", packageName, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.VENDOR, "mix_audit", "Package", packageName, Confidence.HIGH);

        try {
            final PackageURL purl = PackageURLBuilder.aPackageURL().withType("hex").withName(packageName)
                    .withVersion(version).build();
            dep.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
        } catch (MalformedPackageURLException ex) {
            LOGGER.debug("Unable to build package url for hex", ex);
            final GenericIdentifier id = new GenericIdentifier("hex:" + packageName + "@" + version,
                    Confidence.HIGHEST);
            dep.addSoftwareIdentifier(id);
        }

        return dep;
    }

    private Vulnerability createVulnerability(MixAuditResult result) throws CpeValidationException {
        final String product = result.getDependencyPackage();
        final String version = result.getDependencyVersion();

        final Vulnerability vulnerability = new Vulnerability();
        vulnerability.setSource(Vulnerability.Source.MIXAUDIT);

        final VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();
        final VulnerableSoftware vs = builder.part(Part.APPLICATION)
                .vendor(String.format("%s_project", product))
                .product(product)
                .version(version).build();

        vulnerability.addVulnerableSoftware(vs);
        vulnerability.setMatchedVulnerableSoftware(vs);

        vulnerability.setUnscoredSeverity("UNKOWN");
        vulnerability.setDescription(result.getDescription());
        vulnerability.setName(result.getCve());

        return vulnerability;
    }
}
