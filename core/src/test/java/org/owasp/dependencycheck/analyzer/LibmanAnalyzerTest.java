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
 * Copyright (c) 2023 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Arjen Korevaar
 */
class LibmanAnalyzerTest extends BaseTest {

    private Engine engine;
    private LibmanAnalyzer analyzer;

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();

        engine = new Engine(this.getSettings());

        analyzer = new LibmanAnalyzer();
        analyzer.initialize(getSettings());
        analyzer.prepare(engine);
        analyzer.setEnabled(true);
        analyzer.setFilesMatched(true);
    }

    @Test
    void testGetAnalyzerName() {
        String expected = "Libman Analyzer";
        String actual = analyzer.getName();

        assertEquals(expected, actual);
    }

    @Test
    void testSupportedFileNames() {
        boolean condition = analyzer.accept(new File("libman.json"));

        assertTrue(condition);
    }

    @Test
    void testGetAnalyzerEnabledSettingKey() {
        String expected = Settings.KEYS.ANALYZER_LIBMAN_ENABLED;
        String actual = analyzer.getAnalyzerEnabledSettingKey();

        assertEquals(expected, actual);
    }

    @Test
    void testLibmanAnalysis() throws Exception {
        try (Engine engine = new Engine(getSettings())) {
            File file = BaseTest.getResourceAsFile(this, "libman/libman.json");
            Dependency dependency = new Dependency(file);

            analyzer.analyze(dependency, engine);

            int count = 0;

            for (Dependency result : engine.getDependencies()) {
                switch (result.getName()) {
                    case "bootstrap":
                        count++;
                        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("bootstrap"));
                        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("4.6.0"));
                        break;

                    case "jquery":
                        count++;
                        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("jquery"));
                        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("3.6.3"));
                        break;

                    case "font-awesome":
                        count++;
                        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("font-awesome"));
                        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("6.2.1"));
                        break;

                    case "jquery-ui":
                        count++;
                        assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("regru"));
                        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("jquery-ui"));
                        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("1.6.3"));
                        break;

                    default:
                        break;
                }
            }

            assertEquals(4, count, "4 dependencies should be found");
        }
    }
}
