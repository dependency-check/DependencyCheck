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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.lang3.mutable.MutableInt;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.utils.Settings;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author jeremy long
 */
class CPEAnalyzerTest {

    /**
     * Test of getName method, of class CPEAnalyzer.
     */
    @Test
    void testGetName() {
        CPEAnalyzer instance = new CPEAnalyzer();
        String expResult = "CPE Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class CPEAnalyzer.
     */
    @Test
    void testGetAnalysisPhase() {
        CPEAnalyzer instance = new CPEAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.IDENTIFIER_ANALYSIS;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method, of class CPEAnalyzer.
     */
    @Test
    void testGetAnalyzerEnabledSettingKey() {
        CPEAnalyzer instance = new CPEAnalyzer();
        String expResult = Settings.KEYS.ANALYZER_CPE_ENABLED;
        String result = instance.getAnalyzerEnabledSettingKey();
        assertEquals(expResult, result);
    }

    /**
     * Test of collectTerms method, of class CPEAnalyzer.
     */
    @Test
    void testAddEvidenceWithoutDuplicateTerms() {
        Map<String, MutableInt> terms = new HashMap<>();
        List<Evidence> evidence = new ArrayList<>();
        evidence.add(new Evidence("test case", "value", "test", Confidence.HIGHEST));
        CPEAnalyzer instance = new CPEAnalyzer();
        String expResult = "test";
        int expValue = 1;
        instance.collectTerms(terms, evidence);
        assertTrue(terms.containsKey(expResult));
        assertEquals(expValue, terms.get(expResult).intValue());

        evidence = new ArrayList<>();
        evidence.add(new Evidence("test case", "value", "other", Confidence.HIGHEST));
        instance.collectTerms(terms, evidence);
        expResult = "other";
        expValue = 1;
        assertTrue(terms.containsKey(expResult));
        assertEquals(expValue, terms.get(expResult).intValue());

        evidence.clear();
        evidence.add(new Evidence("test case", "value", "other", Confidence.HIGHEST));
        instance.collectTerms(terms, evidence);
        expResult = "other";
        expValue = 2;
        assertTrue(terms.containsKey(expResult));
        assertEquals(expValue, terms.get(expResult).intValue());

        StringBuilder sb = new StringBuilder();
        StringBuilder expect = new StringBuilder();
        for (int x = 0; x < 500; x++) {
            sb.append("items ");
            if (expect.length() + 5 < 1000) {
                expect.append("items ");
            }
        }
        evidence.clear();
        terms.clear();
        evidence.add(new Evidence("test case", "value", sb.toString(), Confidence.HIGHEST));
        instance.collectTerms(terms, evidence);
        expResult = expect.toString().trim();
        expValue = 1;
        assertTrue(terms.containsKey(expResult));
        assertEquals(expValue, terms.get(expResult).intValue());

        sb = new StringBuilder();
        expect = new StringBuilder();
        for (int x = 0; x < 500; x++) {
            sb.append("items.");
            if (expect.length() + 5 < 1000) {
                expect.append("items.");
            }
        }
        evidence.clear();
        terms.clear();
        evidence.add(new Evidence("test case", "value", sb.toString(), Confidence.HIGHEST));
        instance.collectTerms(terms, evidence);
        expect.setLength(expect.length() - 1);
        expResult = expect.toString();
        expValue = 1;
        assertTrue(terms.containsKey(expResult));
        assertEquals(expValue, terms.get(expResult).intValue());

        sb = new StringBuilder();
        expect = new StringBuilder();
        for (int x = 0; x < 500; x++) {
            sb.append("items-");
            if (expect.length() + 5 < 1000) {
                expect.append("items-");
            }
        }
        evidence.clear();
        terms.clear();
        evidence.add(new Evidence("test case", "value", sb.toString(), Confidence.HIGHEST));
        instance.collectTerms(terms, evidence);
        expect.setLength(expect.length() - 1);
        expResult = expect.toString();
        expValue = 1;
        assertTrue(terms.containsKey(expResult));
        assertEquals(expValue, terms.get(expResult).intValue());

        sb = new StringBuilder();
        expect = new StringBuilder();
        for (int x = 0; x < 500; x++) {
            sb.append("items_");
            if (expect.length() + 5 < 1000) {
                expect.append("items_");
            }
        }
        evidence.clear();
        terms.clear();
        evidence.add(new Evidence("test case", "value", sb.toString(), Confidence.HIGHEST));
        instance.collectTerms(terms, evidence);
        expect.setLength(expect.length() - 1);
        expResult = expect.toString();
        expValue = 1;
        assertTrue(terms.containsKey(expResult));
        assertEquals(expValue, terms.get(expResult).intValue());

        sb = new StringBuilder();
        expect = new StringBuilder();
        for (int x = 0; x < 500; x++) {
            sb.append("items/");
            if (expect.length() + 5 < 1000) {
                expect.append("items/");
            }
        }
        evidence.clear();
        terms.clear();
        evidence.add(new Evidence("test case", "value", sb.toString(), Confidence.HIGHEST));
        instance.collectTerms(terms, evidence);
        expect.setLength(expect.length() - 1);
        expResult = expect.toString();
        expValue = 1;
        assertTrue(terms.containsKey(expResult));
        assertEquals(expValue, terms.get(expResult).intValue());
    }

    @Test
    void testCollectTerms() {
        Map<String, MutableInt> terms = new HashMap<>();
        List<Evidence> evidence = new ArrayList<>();
        evidence.add(new Evidence("\\@", "\\*", "\\+", Confidence.HIGHEST));
        CPEAnalyzer instance = new CPEAnalyzer();
        instance.collectTerms(terms, evidence);
        assertTrue(terms.isEmpty());
    }

    /**
     * Test of buildSearch method, of class CPEAnalyzer.
     */
    @Test
    void testBuildSearch() {
        Map<String, MutableInt> vendor = new HashMap<>();
        Map<String, MutableInt> product = new HashMap<>();
        vendor.put("apache software foundation", new MutableInt(1));
        product.put("lucene index", new MutableInt(1));
        Set<String> vendorWeighting = new HashSet<>();
        Set<String> productWeightings = new HashSet<>();

        CPEAnalyzer instance = new CPEAnalyzer();
        String expResult = "product:(lucene index) AND vendor:(apache software foundation)";
        String result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);

        vendorWeighting.add("apache");
        expResult = "product:(lucene index) AND vendor:(apache^2 software foundation)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);

        productWeightings.add("lucene");
        expResult = "product:(lucene^2 index) AND vendor:(apache^2 software foundation)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);

        productWeightings.add("ignored");
        expResult = "product:(lucene^2 index) AND vendor:(apache^2 software foundation)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);

        vendorWeighting.clear();
        expResult = "product:(lucene^2 index) AND vendor:(apache software foundation)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);

        vendorWeighting.add("ignored");
        productWeightings.clear();
        expResult = "product:(lucene index) AND vendor:(apache software foundation)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);

        vendor.put("apache software foundation", new MutableInt(3));
        product.put("lucene index", new MutableInt(2));

        expResult = "product:(lucene^2 index^2) AND vendor:(apache^3 software^3 foundation^3)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);

        vendorWeighting.add("apache");
        expResult = "product:(lucene^2 index^2) AND vendor:(apache^4 software^3 foundation^3)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);

        productWeightings.add("lucene");
        expResult = "product:(lucene^3 index^2) AND vendor:(apache^4 software^3 foundation^3)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);

        productWeightings.clear();
        productWeightings.add("lucene2");
        expResult = "product:(lucene^3 index^2 lucene2^3) AND vendor:(apache^4 software^3 foundation^3)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);

        vendor.put("apache software foundation", new MutableInt(1));
        vendor.put("apache", new MutableInt(2));
        product.put("lucene index", new MutableInt(1));
        product.put("lucene", new MutableInt(2));
        vendorWeighting.clear();
        productWeightings.clear();
        productWeightings.add("lucene2");
        expResult = "product:(lucene^3 lucene2^3 lucene^2 index lucene2^2) AND vendor:(apache^2 apache software foundation)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);
    }

    @Test
    void testBuildSearchBlank() {
        Map<String, MutableInt> vendor = new HashMap<>();
        Map<String, MutableInt> product = new HashMap<>();
        vendor.put("   ", new MutableInt(1));
        product.put("   ", new MutableInt(1));
        Set<String> vendorWeighting = new HashSet<>();
        Set<String> productWeightings = new HashSet<>();

        CPEAnalyzer instance = new CPEAnalyzer();
        String result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertNull(result);
    }
}
