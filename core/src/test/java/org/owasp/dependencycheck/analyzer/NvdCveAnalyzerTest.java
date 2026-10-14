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
 * Copyright (c) 2026 Akhil CH. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

/**
 * Pins down how the analyzer filters the CVEs of a matched CPE by the target
 * software of their vulnerable software entries.
 */
@ExtendWith(MockitoExtension.class)
class NvdCveAnalyzerTest {

    @Mock
    private Engine engine;

    @Mock
    private CveDB cveDB;

    /**
     * A CVE with a single vulnerable software entry, for a dependency with the
     * given ecosystem (empty for none).
     */
    @ParameterizedTest
    @CsvSource({
        "nodejs, *, true",
        "nodejs, -, true",
        "nodejs, node.js, true",
        "nodejs, nodejs, true",
        "nodejs, node_js, true",
        "nodejs, node-js, true",
        "nodejs, npm, true",
        "nodejs, java, false",
        "nodejs, python, false",
        "nodejs, jquery, false",
        "java, *, true",
        "java, -, true",
        "java, java, true",
        "java, android, true",
        "java, node.js, true",
        // CVE-2019-7617 (#3876)
        "java, python, true",
        // CVE-2020-36448 (#6851)
        "java, rust, true",
        "java, go, true",
        "python, java, true",
        "dotnet, wordpress, true",
        "js, python, true",
        "native, python, true",
        ", python, true"
    })
    void testCveWithOneEntry(String ecosystem, String targetSw, boolean kept) throws Exception {
        final Dependency dependency = analyze(ecosystem, vulnerability("CVE-0000-0001", targetSw));
        assertEquals(kept ? List.of("CVE-0000-0001") : List.of(), names(dependency));
    }

    @Test
    void testNodeDependencyKeepsOnlyTheMatchingEntries() throws Exception {
        final Dependency dependency = analyze(Ecosystem.NODEJS,
                vulnerability("CVE-0000-0001", "node.js", "python"),
                vulnerability("CVE-0000-0002", "*", "java"),
                vulnerability("CVE-0000-0003", "java", "python"));
        assertEquals(List.of("CVE-0000-0001", "CVE-0000-0002"), names(dependency));
        assertEquals(List.of("node.js"), targets(dependency, "CVE-0000-0001"));
        assertEquals(List.of("*"), targets(dependency, "CVE-0000-0002"));
    }

    @Test
    void testOtherDependenciesKeepEveryEntry() throws Exception {
        final Dependency dependency = analyze(Ecosystem.JAVA,
                vulnerability("CVE-0000-0001", "java", "python"),
                vulnerability("CVE-0000-0002", "python", "rust"));
        assertEquals(List.of("CVE-0000-0001", "CVE-0000-0002"), names(dependency));
        assertEquals(List.of("java", "python"), targets(dependency, "CVE-0000-0001"));
        assertEquals(List.of("python", "rust"), targets(dependency, "CVE-0000-0002"));
    }

    private Dependency analyze(String ecosystem, Vulnerability... vulnerabilities) throws Exception {
        final CpeIdentifier identifier = new CpeIdentifier("vendor", "product", "1.0", Confidence.HIGHEST);
        when(engine.getDatabase()).thenReturn(cveDB);
        when(cveDB.getVulnerabilities(identifier.getCpe())).thenReturn(new ArrayList<>(List.of(vulnerabilities)));
        final Dependency dependency = new Dependency(true);
        dependency.setEcosystem(ecosystem);
        dependency.addVulnerableSoftwareIdentifier(identifier);
        new NvdCveAnalyzer().analyzeDependency(dependency, engine);
        return dependency;
    }

    private static Vulnerability vulnerability(String name, String... targetSws) throws CpeValidationException {
        final Vulnerability vulnerability = new Vulnerability();
        vulnerability.setName(name);
        for (String targetSw : targetSws) {
            vulnerability.addVulnerableSoftware(new VulnerableSoftwareBuilder().part(Part.APPLICATION)
                    .vendor("vendor").product("product").targetSw(targetSw).vulnerable(true).build());
        }
        return vulnerability;
    }

    private static List<String> names(Dependency dependency) {
        return dependency.getVulnerabilities(true).stream().map(Vulnerability::getName).collect(Collectors.toList());
    }

    private static List<String> targets(Dependency dependency, String name) {
        return dependency.getVulnerabilities().stream().filter(v -> name.equals(v.getName())).findFirst()
                .orElseThrow().getVulnerableSoftware(true).stream()
                .map(VulnerableSoftware::getTargetSw).collect(Collectors.toList());
    }
}
