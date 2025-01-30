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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.concurrent.ThreadSafe;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.analyzer.exception.LambdaExceptionWrapper;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.Vulnerability.Source;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import org.owasp.dependencycheck.utils.Settings;

/**
 * NvdCveAnalyzer is a utility class that takes a project dependency and
 * attempts to discern if there is an associated CVEs. It uses the the
 * identifiers found by other analyzers to lookup the CVE data.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class NvdCveAnalyzer extends AbstractAnalyzer {

    /**
     * Analyzes a dependency and attempts to determine if there are any CPE
     * identifiers for this dependency.
     *
     * @param dependency The Dependency to analyze
     * @param engine The analysis engine
     * @throws AnalysisException thrown if there is an issue analyzing the
     * dependency
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        final CveDB cveDB = engine.getDatabase();
        try {
            dependency.getVulnerableSoftwareIdentifiers().stream()
                    .filter((i) -> (i instanceof CpeIdentifier))
                    .map(i -> (CpeIdentifier) i)
                    .forEach(i -> {
                        try {
                            final List<Vulnerability> vulns = filterEcosystem(dependency.getEcosystem(), cveDB.getVulnerabilities(i.getCpe()));

                            if (Ecosystem.NODEJS.equals(dependency.getEcosystem())) {
                                replaceOrAddVulnerability(dependency, vulns);
                            } else {
                                dependency.addVulnerabilities(vulns);
                            }
                        } catch (DatabaseException ex) {
                            throw new LambdaExceptionWrapper(new AnalysisException(ex));
                        }
                    });
            dependency.getSuppressedIdentifiers().stream()
                    .filter((i) -> (i instanceof CpeIdentifier))
                    .map(i -> (CpeIdentifier) i)
                    .forEach(i -> {
                        try {
                            final List<Vulnerability> vulns = cveDB.getVulnerabilities(i.getCpe());
                            dependency.addSuppressedVulnerabilities(vulns);
                        } catch (DatabaseException ex) {
                            throw new LambdaExceptionWrapper(new AnalysisException(ex));
                        }
                    });
        } catch (LambdaExceptionWrapper ex) {
            throw (AnalysisException) ex.getCause();
        }
    }

    /**
     * Returns the name of this analyzer.
     *
     * @return the name of this analyzer.
     */
    @Override
    public String getName() {
        return "NVD CVE Analyzer";
    }

    /**
     * Returns the analysis phase that this analyzer should run in.
     *
     * @return the analysis phase that this analyzer should run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINDING_ANALYSIS;
    }

    /**
     * <p>
     * Returns the setting key to determine if the analyzer is enabled.</p>
     *
     * @return the key for the analyzer's enabled property
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_NVD_CVE_ENABLED;
    }

    /**
     * Evaluates if the vulnerability is already present; if it is the
     * vulnerability is not added.
     *
     * @param dependency a reference to the dependency being analyzed
     * @param vulns the vulnerability to add
     */
    private void replaceOrAddVulnerability(Dependency dependency, List<Vulnerability> vulns) {
        vulns.forEach(v -> v.getReferences().forEach(ref -> dependency.getVulnerabilities().forEach(existing -> {
                if (existing.getSource() == Source.NPM
                        && ref.getName() != null
                        && ref.getName().equals("https://nodesecurity.io/advisories/" + existing.getName())) {
                    dependency.removeVulnerability(existing);
                }
            })));
        dependency.addVulnerabilities(vulns);
    }

    /**
     * Filters the list of vulnerabilities for the given ecosystem compared to
     * the target software from the NVD.
     *
     * @param ecosystem the dependency's ecosystem
     * @param vulnerabilities the list of vulnerabilities to filter
     * @return the filtered list of vulnerabilities
     */
    private synchronized List<Vulnerability> filterEcosystem(String ecosystem, List<Vulnerability> vulnerabilities) {
        final List<Vulnerability> remove = new ArrayList<>();
        vulnerabilities.forEach((v) -> {
            boolean found = false;
            final Set<VulnerableSoftware> removeSoftware = new HashSet<>();
            for (VulnerableSoftware s : v.getVulnerableSoftware()) {
                if (ecosystemMatchesTargetSoftware(ecosystem, s.getTargetSw())) {
                    found = true;
                } else {
                    removeSoftware.add(s);
                }
            }
            if (found) {
                if (!removeSoftware.isEmpty()) {
                    v.removeVulnerableSoftware(removeSoftware);
                }
            } else {
                remove.add(v);
            }
        });
        if (!remove.isEmpty()) {
            vulnerabilities.removeAll(remove);
        }
        return vulnerabilities;
    }

    /**
     * Determines if the target software matches the given ecosystem. Currently,
     * this is very Node JS specific and broadly returns matches for everything
     * else.
     *
     * @param ecosystem the ecosystem to match against
     * @param targetSoftware the target software from the NVD
     * @return <code>true</code> if there is a match; otherwise
     * <code>false</code>
     */
    private boolean ecosystemMatchesTargetSoftware(String ecosystem, String targetSoftware) {
        if ("*".equals(targetSoftware) || "-".equals(targetSoftware)) {
            return true;
        }
        if (Ecosystem.NODEJS.equals(ecosystem)) {
            switch (targetSoftware.toLowerCase()) {
                case "nodejs":
                case "node.js":
                case "node_js":
                case "npm":
                case "node-js":
                    return true;
                default:
                    return false;
            }
        }
        return true;
    }
}
