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
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class NpmCPEAnalyzerIT extends BaseDBTestCase {

    /**
     * Test of analyzeDependency method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    void testAnalyzeDependency() throws Exception {

        NpmCPEAnalyzer instance = new NpmCPEAnalyzer();
        try (Engine engine = new Engine(getSettings())) {
            // Opening the database in read-only mode always copies the whole database -> open it only once
            engine.openDatabase(true, true);
            instance.initialize(getSettings());
            instance.prepare(engine);

            //callAnalyzeDependency("negotiator", "negotiator", "0.3.0", "cpe:2.3:a:negotiator_project:negotiator:0.3.0:*:*:*:*:*:*:*", instance, engine);
            callAnalyzeDependency("mime", "mime", "1.2.11", "cpe:2.3:a:mime_project:mime:1.2.11:*:*:*:*:*:*:*", instance, engine);

            instance.close();
        }
    }

    /**
     * Executes the test call against AnalyzeDependency.
     *
     * @param vendor
     * @param product
     * @param version
     * @param expectedCpe
     * @param cpeAnalyzer
     * @param engine
     * @throws Exception
     */
    private void callAnalyzeDependency(String vendor, String product, String version, String expectedCpe, NpmCPEAnalyzer cpeAnalyzer, Engine engine) throws Exception {
        Dependency dep = new Dependency(true);
        dep.addEvidence(EvidenceType.VENDOR, "test", "vendor", vendor, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.PRODUCT, "test", "product", product, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.VERSION, "test", "version", version, Confidence.HIGHEST);
        dep.setVersion(version);
        dep.setEcosystem("npm");
        dep.setMd5sum("");
        dep.setSha1sum("");
        dep.setSha256sum("");

        cpeAnalyzer.analyzeDependency(dep, engine);

        boolean found = dep.getVulnerableSoftwareIdentifiers().stream().anyMatch(id -> {
            System.out.println(id.getValue());
            return expectedCpe.equals(id.getValue());
        });
        assertTrue(found, String.format("%s:%s:%s identifier not found", vendor, product, version));
    }

    @Test
    void testAnalyzeDependencyNoMatch() throws Exception {

        NpmCPEAnalyzer instance = new NpmCPEAnalyzer();
        try (Engine engine = new Engine(getSettings())) {
            // Opening the database in read-only mode always copies the whole database -> open it only once
            engine.openDatabase(true, true);
            instance.initialize(getSettings());
            instance.prepare(engine);

            callAnalyzeDependencyNoMatch("npm", "not_going_to_find", "minot_going_to_find_me", "1.2.11", instance, engine);
            callAnalyzeDependencyNoMatch("java", "apache", "commons-httpclient", "3.0", instance, engine);
            instance.close();
        }
    }

    /**
     * Executes the test call against AnalyzeDependency.
     *
     * @param vendor
     * @param product
     * @param version
     * @param engine
     * @throws Exception
     */
    private void callAnalyzeDependencyNoMatch(String ecosystem, String vendor, String product, String version, NpmCPEAnalyzer cpeAnalyzer, Engine engine) throws Exception {
        Dependency dep = new Dependency(true);
        dep.addEvidence(EvidenceType.VENDOR, "test", "vendor", vendor, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.PRODUCT, "test", "product", product, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.VERSION, "test", "version", version, Confidence.HIGHEST);
        dep.setVersion(version);
        dep.setEcosystem(ecosystem);
        dep.setMd5sum("");
        dep.setSha1sum("");
        dep.setSha256sum("");

        cpeAnalyzer.analyzeDependency(dep, engine);
        assertEquals(0, dep.getVulnerableSoftwareIdentifiers().size());
    }
}
