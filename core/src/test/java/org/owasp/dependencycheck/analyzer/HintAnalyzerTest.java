/*
 * Copyright 2014 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class HintAnalyzerTest extends BaseDBTestCase {

    /**
     * Test of getName method, of class HintAnalyzer.
     */
    @Test
    void testGetName() {
        HintAnalyzer instance = new HintAnalyzer();
        String expResult = "Hint Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class HintAnalyzer.
     */
    @Test
    void testGetAnalysisPhase() {
        HintAnalyzer instance = new HintAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.POST_INFORMATION_COLLECTION2;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of analyze method, of class HintAnalyzer.
     */
    @Test
    void testAnalyze() throws Exception {
        File guice = BaseTest.getResourceAsFile(this, "maven-lib/guice-3.0.jar");
        //Dependency guice = new EngineDependency(fileg);
        File spring = BaseTest.getResourceAsFile(this, "spring-core-3.0.0.RELEASE.jar");
        //Dependency spring = new Dependency(files);
        getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        try (Engine engine = new Engine(getSettings())) {
            engine.scan(guice);
            engine.scan(spring);
            engine.analyzeDependencies();
            Dependency gdep = null;
            Dependency sdep = null;
            for (Dependency d : engine.getDependencies()) {
                if (d.getActualFile().equals(guice)) {
                    gdep = d;
                } else if (d.getActualFile().equals(spring)) {
                    sdep = d;
                }
            }
            final Evidence springTest1 = new Evidence("hint analyzer", "product", "springsource_spring_framework", Confidence.HIGHEST, true);
            final Evidence springTest2 = new Evidence("hint analyzer", "vendor", "SpringSource", Confidence.HIGHEST, true);
            final Evidence springTest3 = new Evidence("hint analyzer", "vendor", "vmware", Confidence.HIGHEST, true);
            final Evidence springTest4 = new Evidence("hint analyzer", "product", "springsource_spring_framework", Confidence.HIGHEST, true);
            final Evidence springTest5 = new Evidence("hint analyzer", "vendor", "vmware", Confidence.HIGHEST, true);

            assertFalse(gdep.contains(EvidenceType.PRODUCT, springTest1));
            assertFalse(gdep.contains(EvidenceType.VENDOR, springTest2));
            assertFalse(gdep.contains(EvidenceType.VENDOR, springTest3));
            assertFalse(gdep.contains(EvidenceType.PRODUCT, springTest4));
            assertFalse(gdep.contains(EvidenceType.VENDOR, springTest5));

            assertTrue(sdep.contains(EvidenceType.PRODUCT, springTest1));
            assertTrue(sdep.contains(EvidenceType.VENDOR, springTest2));
            assertTrue(sdep.contains(EvidenceType.VENDOR, springTest3));
            //assertTrue(evidence.contains(springTest4));
            //assertTrue(evidence.contains(springTest5));
        }
    }

    /**
     * Test of analyze method, of class HintAnalyzer.
     */
    @Test
    void testAnalyze_1() throws Exception {
        File path = BaseTest.getResourceAsFile(this, "hints_12.xml");
        getSettings().setString(Settings.KEYS.HINTS_FILE, path.getPath());
        HintAnalyzer instance = new HintAnalyzer();
        instance.initialize(getSettings());
        instance.prepare(null);
        Dependency d = new Dependency();
        d.addEvidence(EvidenceType.VERSION, "version source", "given version name", "1.2.3", Confidence.HIGH);
        d.addEvidence(EvidenceType.VERSION, "hint analyzer", "remove version name", "value", Confidence.HIGH);
        d.addEvidence(EvidenceType.VENDOR, "hint analyzer", "remove vendor name", "vendor", Confidence.HIGH);
        d.addEvidence(EvidenceType.PRODUCT, "hint analyzer", "remove product name", "product", Confidence.HIGH);
        d.addEvidence(EvidenceType.VERSION, "hint analyzer", "other version name", "value", Confidence.HIGH);
        d.addEvidence(EvidenceType.VENDOR, "hint analyzer", "other vendor name", "vendor", Confidence.HIGH);
        d.addEvidence(EvidenceType.PRODUCT, "hint analyzer", "other product name", "product", Confidence.HIGH);

        assertEquals(2, d.getEvidence(EvidenceType.VENDOR).size(), "vendor evidence mismatch");
        assertEquals(2, d.getEvidence(EvidenceType.PRODUCT).size(), "product evidence mismatch");
        assertEquals(3, d.getEvidence(EvidenceType.VERSION).size(), "version evidence mismatch");
        instance.analyze(d, null);
        assertEquals(1, d.getEvidence(EvidenceType.VENDOR).size(), "vendor evidence mismatch");
        assertEquals(1, d.getEvidence(EvidenceType.PRODUCT).size(), "product evidence mismatch");
        assertEquals(2, d.getEvidence(EvidenceType.VERSION).size(), "version evidence mismatch");
    }

    @Nested
    class CoreHintsLoading {
        @Test
        void testLoadCorePackagedHints() throws Exception {
            getSettings().removeProperty(Settings.KEYS.HINTS_FILE);
            HintAnalyzer instance = new HintAnalyzer();
            instance.initialize(getSettings());
            instance.prepare(null);

            assertThat(List.of(instance.getHintRules()), not(empty()));
            assertThat(List.of(instance.getVendorDuplicatingHintRules()), not(empty()));
        }
    }
}
