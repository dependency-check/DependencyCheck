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
 * Copyright (c) 2018 Paul Irwin. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.owasp.dependencycheck.analyzer.NuspecAnalyzer.DEPENDENCY_ECOSYSTEM;

class NugetconfAnalyzerTest extends BaseTest {

    private NugetconfAnalyzer instance;

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        instance = new NugetconfAnalyzer();
        instance.initialize(getSettings());
        instance.prepare(null);
        instance.setEnabled(true);
    }

    @Test
    void testGetAnalyzerName() {
        assertEquals("Nugetconf Analyzer", instance.getName());
    }

    @Test
    void testSupportedFileNames() {
        assertTrue(instance.accept(new File("packages.config")));
        assertFalse(instance.accept(new File("packages.json")));
    }

    @Test
    void testNugetconfAnalysis() throws Exception {

        try (Engine engine = new Engine(getSettings())) {
            File file = BaseTest.getResourceAsFile(this, "nugetconf/packages.config");
            Dependency toScan = new Dependency(file);
            NugetconfAnalyzer analyzer = new NugetconfAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            analyzer.setEnabled(true);
            analyzer.analyze(toScan, engine);

            int foundCount = 0;

            for (Dependency result : engine.getDependencies()) {
                assertEquals(DEPENDENCY_ECOSYSTEM, result.getEcosystem());
                assertTrue(result.isVirtual());

                switch(result.getName()) {
                    case "Autofac":
                        foundCount++;
                        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Autofac"));
                        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("4.6.2"));
                        break;

                    case "Microsoft.AspNet.WebApi.Core":
                        foundCount++;
                        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Microsoft.AspNet.WebApi.Core"));
                        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("5.2.4"));
                        break;

                    case "Microsoft.Owin":
                        foundCount++;
                        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Microsoft.Owin"));
                        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("3.1.0"));
                        break;

                    case "Newtonsoft.Json":
                        foundCount++;
                        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Newtonsoft.Json"));
                        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("10.0.3"));
                        break;

                    default :
                        break;
                    }
                }
            assertEquals(4, foundCount, "4 dependencies should be found");
        }
    }
}
