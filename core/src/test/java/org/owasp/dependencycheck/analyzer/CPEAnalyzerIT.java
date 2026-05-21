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

import org.apache.commons.lang3.mutable.MutableInt;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.cpe.IndexEntry;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.Identifier;

import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 *
 * @author Jeremy Long
 */
class CPEAnalyzerIT extends BaseDBTestCase {

    /**
     * Tests of buildSearch of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an IO Exception occurs.
     */
    @Test
    void testBuildSearch() throws Exception {
        Set<String> productWeightings = new HashSet<>();//Collections.singleton("struts2");
        Set<String> vendorWeightings = new HashSet<>();//Collections.singleton("apache");
        Map<String, MutableInt> vendor = new HashMap<>();
        Map<String, MutableInt> product = new HashMap<>();
        vendor.put("apache software foundation", new MutableInt(1));
        product.put("struts 2 core", new MutableInt(1));

        CPEAnalyzer instance = new CPEAnalyzer();
        instance.initialize(getSettings());
        String queryText = instance.buildSearch(vendor, product, vendorWeightings, productWeightings);
        String expResult = "product:(struts 2 core) AND vendor:(apache software foundation)";
        assertEquals(expResult, queryText);

        vendorWeightings.add("apache");
        productWeightings.add("struts2");

        queryText = instance.buildSearch(vendor, product, vendorWeightings, productWeightings);
        expResult = "product:(struts^2 2 core struts2^2) AND vendor:(apache^2 software foundation)";
        assertEquals(expResult, queryText);
        instance.close();
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    void testDetermineCPE_full() throws Exception {
        CPEAnalyzer cpeAnalyzer = new CPEAnalyzer();
        try (Engine e = new Engine(getSettings())) {
            //update needs to be performed so that xtream can be tested
            //e.doUpdates(true);
            e.openDatabase(true, true);
            cpeAnalyzer.initialize(getSettings());
            cpeAnalyzer.prepare(e);
            FileNameAnalyzer fnAnalyzer = new FileNameAnalyzer();
            fnAnalyzer.initialize(getSettings());
            fnAnalyzer.prepare(e);
            JarAnalyzer jarAnalyzer = new JarAnalyzer();
            jarAnalyzer.initialize(getSettings());
            jarAnalyzer.accept(new File("test.jar"));//trick analyzer into "thinking it is active"
            jarAnalyzer.prepare(e);
            HintAnalyzer hAnalyzer = new HintAnalyzer();
            hAnalyzer.initialize(getSettings());
            hAnalyzer.prepare(e);
            FalsePositiveAnalyzer fp = new FalsePositiveAnalyzer();
            fp.initialize(getSettings());
            fp.prepare(e);

            CpeSuppressionAnalyzer cpeSuppression = new CpeSuppressionAnalyzer();
            cpeSuppression.initialize(getSettings());
            cpeSuppression.prepare(e);

            callDetermineCPE_full("maven-lib/spring-context-support-2.5.5.jar", "cpe:2.3:a:springsource:spring_framework:2.5.5:*:*:*:*:*:*:*", cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp, cpeSuppression);
            callDetermineCPE_full("spring-core-3.0.0.RELEASE.jar", "cpe:2.3:a:pivotal_software:spring_framework:3.0.0:release:*:*:*:*:*:*", cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp, cpeSuppression);
            callDetermineCPE_full("spring-core-3.0.0.RELEASE.jar", "cpe:2.3:a:springsource:spring_framework:3.0.0:release:*:*:*:*:*:*", cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp, cpeSuppression);
            callDetermineCPE_full("jaxb-xercesImpl-1.5.jar", null, cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp, cpeSuppression);
            callDetermineCPE_full("maven-lib/ehcache-core-2.2.0.jar", null, cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp, cpeSuppression);
            callDetermineCPE_full("maven-lib/xstream-1.4.8.jar", "cpe:2.3:a:xstream_project:xstream:1.4.8:*:*:*:*:*:*:*", cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp, cpeSuppression);
        } finally {
            cpeAnalyzer.close();
        }
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     *
     * @param depName dependency name
     * @param expResult expected results
     * @param cpeAnalyzer the CPE analyzer
     * @param fnAnalyzer the file name analyzer
     * @param jarAnalyzer the jar analyzer
     * @param hAnalyzer the hint analyzer
     * @param fp the false positive analyzer
     * @param cpeSuppression the CPE suppression analyzer
     * @throws Exception is thrown when an exception occurs
     */
    private void callDetermineCPE_full(String depName, String expResult, CPEAnalyzer cpeAnalyzer, FileNameAnalyzer fnAnalyzer,
            JarAnalyzer jarAnalyzer, HintAnalyzer hAnalyzer, FalsePositiveAnalyzer fp, CpeSuppressionAnalyzer cpeSuppression) throws Exception {

        File file = BaseTest.getResourceAsFile(this, depName);

        Dependency dep = new Dependency(file);

        fnAnalyzer.analyze(dep, null);
        jarAnalyzer.analyze(dep, null);
        hAnalyzer.analyze(dep, null);
        cpeAnalyzer.analyze(dep, null);
        fp.analyze(dep, null);
        cpeSuppression.analyze(dep, null);

        if (expResult != null) {
            boolean found = false;
            for (Identifier i : dep.getVulnerableSoftwareIdentifiers()) {
                if (expResult.equals(i.getValue())) {
                    found = true;
                    break;
                }
            }
            assertTrue(found, "Match not found: { dep:'" + dep.getFileName() + "', exp:'" + expResult + "' }");
        } else {
            dep.getVulnerableSoftwareIdentifiers().forEach(id -> fail("Unexpected match found: { dep:'" + dep.getFileName() + "', found:'" + id + "' }"));
        }
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    void testDetermineCPE() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "maven-lib/struts2-core-2.1.2.jar");
        Dependency struts = new Dependency(file);
        try (Engine engine = new Engine(getSettings())) {
            CpeSuppressionAnalyzer suppressionAnalyzer = new CpeSuppressionAnalyzer();
            suppressionAnalyzer.initialize(getSettings());
            suppressionAnalyzer.prepare(engine);

            FileNameAnalyzer fnAnalyzer = new FileNameAnalyzer();
            fnAnalyzer.analyze(struts, engine);

            HintAnalyzer hintAnalyzer = new HintAnalyzer();
            hintAnalyzer.initialize(getSettings());
            hintAnalyzer.prepare(engine);
            JarAnalyzer jarAnalyzer = new JarAnalyzer();
            jarAnalyzer.initialize(getSettings());
            jarAnalyzer.accept(new File("test.jar"));//trick analyzer into "thinking it is active"
            jarAnalyzer.prepare(engine);

            jarAnalyzer.analyze(struts, engine);
            hintAnalyzer.analyze(struts, engine);
            File fileCommonValidator = BaseTest.getResourceAsFile(this, "commons-validator-1.4.0.jar");
            Dependency commonValidator = new Dependency(fileCommonValidator);
            jarAnalyzer.analyze(commonValidator, engine);
            hintAnalyzer.analyze(commonValidator, engine);

            File fileSpring = BaseTest.getResourceAsFile(this, "maven-lib/spring-core-2.5.5.jar");
            Dependency spring = new Dependency(fileSpring);
            jarAnalyzer.analyze(spring, engine);
            hintAnalyzer.analyze(spring, engine);

            File fileSpring3 = BaseTest.getResourceAsFile(this, "spring-core-3.0.0.RELEASE.jar");
            Dependency spring3 = new Dependency(fileSpring3);
            jarAnalyzer.analyze(spring3, engine);
            hintAnalyzer.analyze(spring3, engine);

            CPEAnalyzer instance = new CPEAnalyzer();

            engine.openDatabase(true, true);
            instance.initialize(getSettings());
            instance.prepare(engine);
            instance.determineCPE(commonValidator);
            instance.determineCPE(struts);
            instance.determineCPE(spring);
            instance.determineCPE(spring3);
            instance.close();

            suppressionAnalyzer.analyze(commonValidator, engine);
            commonValidator.getVulnerableSoftwareIdentifiers().forEach(i -> fail("Apache Common Validator found an unexpected CPE identifier - " + i.getValue()));

            String expResult = "cpe:2.3:a:apache:struts:2.1.2:*:*:*:*:*:*:*";
            assertFalse(struts.getVulnerableSoftwareIdentifiers().isEmpty(), "Incorrect match size - struts");
            boolean found = false;
            for (Identifier i : struts.getVulnerableSoftwareIdentifiers()) {
                if (expResult.equals(i.getValue())) {
                    found = true;
                    break;
                }
            }
            assertTrue(found, "Incorrect match - struts");
            assertFalse(spring3.getVulnerableSoftwareIdentifiers().isEmpty(), "Incorrect match size - spring3 - " + spring3.getVulnerableSoftwareIdentifiers().size());

            jarAnalyzer.close();
            suppressionAnalyzer.close();
        }
    }

    /**
     * Test of determineIdentifiers method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    void testDetermineIdentifiers() throws Exception {

        CPEAnalyzer instance = new CPEAnalyzer();
        try (Engine engine = new Engine(getSettings())) {
            // Opening the database in read-only mode always copies the whole database -> open it only once
            engine.openDatabase(true, true);
            instance.initialize(getSettings());
            instance.prepare(engine);

            callDetermieIdentifiers("pivotal_software", "spring_framework", "4.3.4.release", "cpe:2.3:a:pivotal_software:spring_framework:4.3.4:release:*:*:*:*:*:*", instance);
            callDetermieIdentifiers("eclipse", "jetty", "20.4.8.v20171121", "cpe:2.3:a:eclipse:jetty:20.4.8:20171121:*:*:*:*:*:*", instance);
            callDetermieIdentifiers("openssl", "openssl", "1.0.1c", "cpe:2.3:a:openssl:openssl:1.0.1c:*:*:*:*:*:*:*", instance);
            //requires 2018 NVD CVE data to identify this. Removing in order to speed build
            //callDetermieIdentifiers("jrebel", "zt-zip", "1.0", "cpe:2.3:a:jrebel:zt-zip:1.0:*:*:*:*:*:*:*", instance);

            instance.close();
        }
    }

    /**
     * Executes the test call against DetermineIdentifiers.
     *
     * @param vendor
     * @param product
     * @param version
     * @param expectedCpe
     * @param cpeAnalyzer
     * @throws Exception
     */
    private void callDetermieIdentifiers(String vendor, String product, String version, String expectedCpe, CPEAnalyzer cpeAnalyzer) throws Exception {
        Dependency dep = new Dependency();
        dep.addEvidence(EvidenceType.VENDOR, "test", "vendor", vendor, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.PRODUCT, "test", "product", product, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.VERSION, "test", "version", version, Confidence.HIGHEST);

        cpeAnalyzer.determineIdentifiers(dep, vendor, product, Confidence.HIGHEST);

        boolean found = dep.getVulnerableSoftwareIdentifiers().stream().anyMatch(id -> {
            System.out.println(id.getValue());
            return expectedCpe.equals(id.getValue());
        });
        assertTrue(found, String.format("%s:%s:%s identifier not found", vendor, product, version));
    }

    /**
     * Test of analyzeDependency method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    void testAnalyzeDependency() throws Exception {

        CPEAnalyzer instance = new CPEAnalyzer();
        try (Engine engine = new Engine(getSettings())) {
            // Opening the database in read-only mode always copies the whole database -> open it only once
            engine.openDatabase(true, true);
            instance.initialize(getSettings());
            instance.prepare(engine);

            callAnalyzeDependency("eclipse", "jetty", "20.4.8.v20171121", "cpe:2.3:a:eclipse:jetty:20.4.8:20171121:*:*:*:*:*:*", instance, engine);
            callAnalyzeDependency("openssl", "openssl", "1.0.1c", "cpe:2.3:a:openssl:openssl:1.0.1c:*:*:*:*:*:*:*", instance, engine);
            callAnalyzeDependency("apache", "commons-httpclient", "3.0", "cpe:2.3:a:apache:httpclient:3.0:*:*:*:*:*:*:*", instance, engine);
            //requires 2018 NVD CVE data to identify this. Removing in order to speed build
            //callAnalyzeDependency("jrebel", "zt-zip", "1.0", "cpe:2.3:a:jrebel:zt-zip:1.0:*:*:*:*:*:*:*", instance, engine);

            // Non-exact matches
            callAnalyzeDependency("org.apache", "commons-httpclient", "3.0", "cpe:2.3:a:apache:httpclient:3.0:*:*:*:*:*:*:*", instance, engine);
            callAnalyzeDependency("org.apache", "httpclient", "3.0", "cpe:2.3:a:apache:httpclient:3.0:*:*:*:*:*:*:*", instance, engine);
            //requires 2018 NVD CVE data to identify this. Removing in order to speed build
            //callAnalyzeDependency("org.jrebel", "zt-zip", "1.0", "cpe:2.3:a:jrebel:zt-zip:1.0:*:*:*:*:*:*:*", instance, engine);

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
    private void callAnalyzeDependency(String vendor, String product, String version, String expectedCpe, CPEAnalyzer cpeAnalyzer, Engine engine) throws Exception {
        Dependency dep = new Dependency(true);
        dep.addEvidence(EvidenceType.VENDOR, "test", "vendor", vendor, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.PRODUCT, "test", "product", product, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.VERSION, "test", "version", version, Confidence.HIGHEST);
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

    /**
     * Test of searchCPE method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    void testSearchCPE() throws Exception {
        Map<String, MutableInt> vendor = new HashMap<>();
        Map<String, MutableInt> product = new HashMap<>();
        vendor.put("apache software foundation", new MutableInt(1));
        product.put("struts 2 core", new MutableInt(1));

        String expVendor = "apache";
        String expProduct = "struts";

        CPEAnalyzer instance = new CPEAnalyzer();
        try (Engine engine = new Engine(getSettings())) {
            engine.openDatabase(true, true);
            instance.initialize(getSettings());
            instance.prepare(engine);

            Set<String> productWeightings = Collections.singleton("struts2");
            Set<String> vendorWeightings = Collections.singleton("apache");
            List<IndexEntry> result = instance.searchCPE(vendor, product, vendorWeightings, productWeightings, Ecosystem.JAVA);

            boolean found = false;
            for (IndexEntry entry : result) {
                if (expVendor.equals(entry.getVendor()) && expProduct.equals(entry.getProduct())) {
                    found = true;
                    break;
                }
            }
            assertTrue(found, "apache:struts was not identified");
        }
        instance.close();
    }
}
