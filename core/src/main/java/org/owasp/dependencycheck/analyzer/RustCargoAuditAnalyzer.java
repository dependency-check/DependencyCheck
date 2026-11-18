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
package org.owasp.dependencycheck.analyzer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import java.io.FileFilter;
import java.io.IOException;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.processing.ProcessReader;

@Experimental
public class RustCargoAuditAnalyzer extends AbstractFileTypeAnalyzer {

    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addFilenames("Cargo.lock").build();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_CARGO_AUDIT_ENABLED;
    }

    @Override
    public String getName() {
        return "Rust Cargo Audit Analyzer";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.PRE_INFORMATION_COLLECTION;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        try {
            run("cargo", "audit", "--version");
        } catch (AnalysisException ex) {
            setEnabled(false);
            throw new InitializationException("Install cargo-audit to analyze Cargo.lock files", ex);
        }
    }

    private String run(String... command) throws AnalysisException {
        try {
            final Process process = new ProcessBuilder(command).start();
            final ProcessReader reader = new ProcessReader(process);
            reader.readAll();
            if (process.exitValue() > 1 || reader.getOutput().isBlank()) {
                throw new AnalysisException("cargo audit failed: " + reader.getError());
            }
            return reader.getOutput();
        } catch (IOException ex) {
            throw new AnalysisException("Could not run cargo audit", ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new AnalysisException("cargo audit was interrupted", ex);
        }
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        final String output = run("cargo", "audit", "--json", "--file", dependency.getActualFile().getAbsolutePath());
        for (Dependency crate : parseReport(output, dependency, engine.getDatabase())) {
            engine.addDependency(crate);
        }
    }

    Collection<Dependency> parseReport(String output, Dependency lockfile, CveDB database) throws AnalysisException {
        final Map<String, Dependency> crates = new LinkedHashMap<>();
        try {
            final JsonNode report = MAPPER.readTree(output);
            final JsonNode vulnerabilities = report.required("vulnerabilities").required("list");
            for (JsonNode finding : MAPPER.treeToValue(vulnerabilities.requireNonNull(), JsonNode[].class)) {
                final Dependency crate = dependency(crates, lockfile, finding);
                crate.addVulnerability(vulnerability(finding.required("advisory"), database));
            }
        } catch (IOException | IllegalArgumentException | MalformedPackageURLException ex) {
            throw new AnalysisException("Invalid cargo audit report", ex);
        }
        return crates.values();
    }

    private Vulnerability vulnerability(JsonNode advisory, CveDB database) {
        final String id = advisory.required("id").asText();
        Vulnerability vulnerability = null;
        for (JsonNode alias : advisory.path("aliases")) {
            if (database != null && alias.asText().startsWith("CVE-")) {
                vulnerability = database.getVulnerability(alias.asText());
                if (vulnerability != null) {
                    break;
                }
            }
        }
        if (vulnerability == null) {
            vulnerability = new Vulnerability();
            vulnerability.setSource(Vulnerability.Source.RUSTSEC);
            vulnerability.setName(id);
            vulnerability.setDescription(advisory.required("description").asText());
            vulnerability.setUnscoredSeverity("UNKNOWN");
        }
        vulnerability.addReference("RustSec", id, "https://rustsec.org/advisories/" + id + ".html");
        return vulnerability;
    }

    private Dependency dependency(Map<String, Dependency> crates, Dependency lockfile, JsonNode finding) throws MalformedPackageURLException {
        final JsonNode pkg = finding.required("package");
        final String name = pkg.required("name").asText();
        final String version = pkg.required("version").asText();
        final PurlIdentifier purl = new PurlIdentifier("cargo", name, version, Confidence.HIGHEST);
        return crates.computeIfAbsent(purl.getValue(), key -> {
            final Dependency dep = new Dependency(lockfile.getActualFile(), true);
            dep.setName(name);
            dep.setVersion(version);
            dep.setEcosystem(Ecosystem.RUST);
            dep.setDisplayFileName(name + ":" + version);
            dep.setPackagePath(key);
            dep.setMd5sum(Checksum.getMD5Checksum(key));
            dep.setSha1sum(Checksum.getSHA1Checksum(key));
            dep.setSha256sum(Checksum.getSHA256Checksum(key));
            dep.addSoftwareIdentifier(purl);
            return dep;
        });
    }
}
