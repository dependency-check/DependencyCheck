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
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2Data;
import org.owasp.dependencycheck.Engine;
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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.owasp.dependencycheck.analyzer.RubyBundleAuditAnalyzer.ADVISORY;
import static org.owasp.dependencycheck.analyzer.RubyBundleAuditAnalyzer.CRITICALITY;
import static org.owasp.dependencycheck.analyzer.RubyBundleAuditAnalyzer.CVE;
import static org.owasp.dependencycheck.analyzer.RubyBundleAuditAnalyzer.DEPENDENCY_ECOSYSTEM;
import static org.owasp.dependencycheck.analyzer.RubyBundleAuditAnalyzer.NAME;
import static org.owasp.dependencycheck.analyzer.RubyBundleAuditAnalyzer.VERSION;

/**
 * Processor for the output of bundler-audit.
 *
 * @author Jeremy Long
 */
public class BundlerAuditProcessor extends Processor<InputStream> {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(BundlerAuditProcessor.class);
    /**
     * Reference to the gem lock dependency.
     */
    private final Dependency gemDependency;
    /**
     * Reference to the dependency-check engine.
     */
    private final Engine engine;
    /**
     * Temporary storage for an exception if it occurs during the processing.
     */
    private IOException ioException;
    /**
     * Temporary storage for an exception if it occurs during the processing.
     */
    private CpeValidationException cpeException;

    /**
     * Constructs a new processor to consume the output of `bundler-audit`.
     *
     * @param gemDependency a reference to `gem.lock` dependency
     * @param engine a reference to the dependency-check engine
     */
    public BundlerAuditProcessor(Dependency gemDependency, Engine engine) {
        this.gemDependency = gemDependency;
        this.engine = engine;
    }

    /**
     * Throws any exceptions that occurred during processing.
     *
     * @throws IOException thrown if an IO Exception occurred
     * @throws CpeValidationException thrown if a CPE validation exception
     * occurred
     */
    @Override
    public void close() throws IOException, CpeValidationException {
        if (ioException != null) {
            addSuppressedExceptions(ioException, cpeException);
            throw ioException;
        }
        if (cpeException != null) {
            throw cpeException;
        }
    }

    @Override
    public void run() {
        final String parentName = gemDependency.getActualFile().getParentFile().getName();
        final String fileName = gemDependency.getFileName();
        final String filePath = gemDependency.getFilePath();
        Dependency dependency = null;
        Vulnerability vulnerability = null;
        String gem = null;
        final Map<String, Dependency> map = new HashMap<>();
        boolean appendToDescription = false;

        try (InputStreamReader ir = new InputStreamReader(getInput(), StandardCharsets.UTF_8); BufferedReader br = new BufferedReader(ir)) {

            String nextLine;
            while ((nextLine = br.readLine()) != null) {
                if (nextLine.startsWith(NAME)) {
                    appendToDescription = false;
                    gem = nextLine.substring(NAME.length());
                    if (!map.containsKey(gem)) {
                        map.put(gem, createDependencyForGem(engine, gemDependency.getActualFile(), parentName, fileName, filePath, gem));
                    }
                    dependency = map.get(gem);
                    LOGGER.debug("bundle-audit ({}): {}", parentName, nextLine);
                } else if (nextLine.startsWith(VERSION)) {
                    vulnerability = createVulnerability(parentName, dependency, gem, nextLine);
                } else if (nextLine.startsWith(ADVISORY) || nextLine.startsWith(CVE)) {
                    setVulnerabilityName(parentName, dependency, vulnerability, nextLine);
                } else if (nextLine.startsWith(CRITICALITY)) {
                    addCriticalityToVulnerability(parentName, vulnerability, nextLine);
                } else if (nextLine.startsWith("URL: ")) {
                    addReferenceToVulnerability(parentName, vulnerability, nextLine);
                } else if (nextLine.startsWith("Description:") || nextLine.startsWith("Title:")) {
                    appendToDescription = true;
                    if (null != vulnerability) {
                        vulnerability.setDescription("*** Vulnerability obtained from bundle-audit verbose report. "
                                + "Title link may not work. CPE below is guessed. CVSS score is estimated (-1.0 "
                                + " indicates unknown). See link below for full details. *** ");
                    }
                } else if (appendToDescription && null != vulnerability) {
                    vulnerability.setDescription(vulnerability.getDescription() + nextLine + "\n");
                }
            }
        } catch (IOException ex) {
            this.ioException = ex;
        } catch (CpeValidationException ex) {
            this.cpeException = ex;
        }
    }

    /**
     * Sets the vulnerability name.
     *
     * @param parentName the parent name
     * @param dependency the dependency
     * @param vulnerability the vulnerability
     * @param nextLine the line to parse
     */
    private void setVulnerabilityName(String parentName, Dependency dependency, Vulnerability vulnerability, String nextLine) {
        final String advisory;
        if (nextLine.startsWith(CVE)) {
            advisory = nextLine.substring(CVE.length());
        } else {
            advisory = nextLine.substring(ADVISORY.length());
        }
        if (null != vulnerability) {
            vulnerability.setName(advisory);
        }
        if (null != dependency) {
            dependency.addVulnerability(vulnerability);
        }
        LOGGER.debug("bundle-audit ({}): {}", parentName, nextLine);
    }

    /**
     * Adds a reference to the vulnerability.
     *
     * @param parentName the parent name
     * @param vulnerability the vulnerability
     * @param nextLine the line to parse
     */
    private void addReferenceToVulnerability(String parentName, Vulnerability vulnerability, String nextLine) {
        final String url = nextLine.substring("URL: ".length());
        if (null != vulnerability) {
            final Reference ref = new Reference();
            ref.setName(vulnerability.getName());
            ref.setSource("bundle-audit");
            ref.setUrl(url);
            vulnerability.getReferences().add(ref);
        }
        LOGGER.debug("bundle-audit ({}): {}", parentName, nextLine);
    }

    /**
     * Adds the criticality to the vulnerability
     *
     * @param parentName the parent name
     * @param vulnerability the vulnerability
     * @param nextLine the line to parse
     */
    private void addCriticalityToVulnerability(String parentName, Vulnerability vulnerability, String nextLine) {
        if (null != vulnerability) {
            final String criticality = nextLine.substring(CRITICALITY.length()).trim();
            Double score = -1.0;
            Vulnerability v = null;
            final CveDB cvedb = engine.getDatabase();
            if (cvedb != null) {
                try {
                    v = cvedb.getVulnerability(vulnerability.getName());
                } catch (DatabaseException ex) {
                    LOGGER.debug("Unable to look up vulnerability {}", vulnerability.getName());
                }
            }
            if (v != null && (v.getCvssV2() != null || v.getCvssV3() != null)) {
                if (v.getCvssV2() != null) {
                    vulnerability.setCvssV2(v.getCvssV2());
                }
                if (v.getCvssV3() != null) {
                    vulnerability.setCvssV3(v.getCvssV3());
                }
            } else {
                if ("High".equalsIgnoreCase(criticality)) {
                    score = 8.5;
                } else if ("Medium".equalsIgnoreCase(criticality)) {
                    score = 5.5;
                } else if ("Low".equalsIgnoreCase(criticality)) {
                    score = 2.0;
                }
                LOGGER.debug("bundle-audit vulnerability missing CVSS data: {}", vulnerability.getName());
                final CvssV2Data cvssData = new CvssV2Data("2.0", null, null, null, null, null, null, null, score, criticality.toUpperCase(),
                        null, null, null, null, null, null, null, null, null, null);
                final CvssV2 cvssV2 = new CvssV2(null, null, cvssData, criticality.toUpperCase(), null, null, null, null, null, null, null);
                vulnerability.setCvssV2(cvssV2);
                vulnerability.setUnscoredSeverity(null);
            }
        }
        LOGGER.debug("bundle-audit ({}): {}", parentName, nextLine);
    }

    /**
     * Creates a vulnerability.
     *
     * @param parentName the parent name
     * @param dependency the dependency
     * @param gem the gem name
     * @param nextLine the line to parse
     * @return the vulnerability
     * @throws CpeValidationException thrown if there is an error building the
     * CPE vulnerability object
     */
    private Vulnerability createVulnerability(String parentName, Dependency dependency, String gem, String nextLine) throws CpeValidationException {
        Vulnerability vulnerability = null;
        if (null != dependency) {
            final String version = nextLine.substring(VERSION.length());
            dependency.addEvidence(EvidenceType.VERSION,
                    "bundler-audit",
                    "Version",
                    version,
                    Confidence.HIGHEST);
            dependency.setVersion(version);
            dependency.setName(gem);
            try {
                final PackageURL purl = PackageURLBuilder.aPackageURL().withType("gem").withName(dependency.getName())
                        .withVersion(dependency.getVersion()).build();
                dependency.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
            } catch (MalformedPackageURLException ex) {
                LOGGER.debug("Unable to build package url for python", ex);
                final GenericIdentifier id = new GenericIdentifier("gem:" + dependency.getName() + "@" + dependency.getVersion(),
                        Confidence.HIGHEST);
                dependency.addSoftwareIdentifier(id);
            }

            vulnerability = new Vulnerability(); // don't add to dependency until we have name set later
            vulnerability.setSource(Vulnerability.Source.BUNDLEAUDIT);
            final VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();
            final VulnerableSoftware vs = builder.part(Part.APPLICATION)
                    .vendor(gem)
                    .product(String.format("%s_project", gem))
                    .version(version).build();
            vulnerability.addVulnerableSoftware(vs);
            vulnerability.setMatchedVulnerableSoftware(vs);
            vulnerability.setUnscoredSeverity("UNKNOWN");
        }
        LOGGER.debug("bundle-audit ({}): {}", parentName, nextLine);
        return vulnerability;
    }

    /**
     * Creates the dependency based off of the gem.
     *
     * @param engine the engine used for scanning
     * @param gemFile the gem file
     * @param parentName the gem parent
     * @param fileName the file name
     * @param filePath the file path
     * @param gem the gem name
     * @return the dependency to add
     * @throws IOException thrown if a temporary gem file could not be written
     */
    private Dependency createDependencyForGem(Engine engine, File gemFile, String parentName, String fileName,
            String filePath, String gem) throws IOException {
        final String displayFileName = String.format("%s%c%s:%s", parentName, File.separatorChar, fileName, gem);
        final Dependency dependency = new Dependency(gemFile, true);
        dependency.setSha1sum(Checksum.getSHA1Checksum(displayFileName));
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
        dependency.addEvidence(EvidenceType.PRODUCT, "bundler-audit", "Name", gem, Confidence.HIGHEST);
        //TODO add package URL - note, this may require parsing the gemfile.lock and getting the version for each entry

        dependency.setDisplayFileName(displayFileName);
        dependency.setFileName(fileName);
        dependency.setFilePath(filePath);
        //sha1sum is used for anchor links in the HtML report
        dependency.setSha1sum(Checksum.getSHA1Checksum(displayFileName));
        engine.addDependency(dependency);
        return dependency;
    }
}
