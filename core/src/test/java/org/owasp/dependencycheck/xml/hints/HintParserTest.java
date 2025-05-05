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
 * Copyright (c) 2016 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.hints;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import java.io.File;
import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class HintParserTest extends BaseTest {

    /**
     * Test of parseHints method, of class HintParser.
     */
    @Test
    void testParseHints_File() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "hints.xml");
        HintParser instance = new HintParser();
        instance.parseHints(file);
        List<HintRule> hintRules = instance.getHintRules();
        List<VendorDuplicatingHintRule> vendorRules = instance.getVendorDuplicatingHintRules();
        assertEquals(2, vendorRules.size(), "Two duplicating hints should have been read");
        assertEquals(2, hintRules.size(), "Two hint rules should have been read");

        assertEquals(1, hintRules.get(0).getAddProduct().size(), "One add product should have been read");
        assertEquals(1, hintRules.get(0).getAddVendor().size(), "One add vendor should have been read");
        assertEquals(2, hintRules.get(1).getFileNames().size(), "Two file name should have been read");

        assertEquals("add product name", hintRules.get(0).getAddProduct().get(0).getName(), "add product name not found");
        assertEquals("add vendor name", hintRules.get(0).getAddVendor().get(0).getName(), "add vendor name not found");
        assertEquals("given product name", hintRules.get(0).getGivenProduct().get(0).getName(), "given product name not found");
        assertEquals("given vendor name", hintRules.get(0).getGivenVendor().get(0).getName(), "given vendor name not found");

        assertEquals("spring", hintRules.get(1).getFileNames().get(0).getValue(), "spring file name not found");
        assertFalse(hintRules.get(1).getFileNames().get(0).isCaseSensitive(), "file name 1 should not be case sensitive");
        assertFalse(hintRules.get(1).getFileNames().get(0).isRegex(), "file name 1 should not be a regex");
        assertTrue(hintRules.get(1).getFileNames().get(1).isCaseSensitive(), "file name 2 should be case sensitive");
        assertTrue(hintRules.get(1).getFileNames().get(1).isRegex(), "file name 2 should be a regex");

        assertEquals("sun", vendorRules.get(0).getValue(), "sun duplicating vendor");
        assertEquals("oracle", vendorRules.get(0).getDuplicate(), "sun duplicates vendor oracle");
    }

    /**
     * Test the application of the correct XSD by the parser by using a
     * hints-file with namespace
     * {@code https://jeremylong.github.io/DependencyCheck/dependency-hint.1.1.xsd}
     * that is using the version evidence for {@code<given>} that was introduced
     * with namespace
     * {@code https://jeremylong.github.io/DependencyCheck/dependency-hint.1.2.xsd}.
     * This should yield a specific SAXParseException that gets wrapped into a
     * HintParseException. We check for the correct error by searching for the
     * error-message of the SAXParser in the exception's message.
     */
    @Test
    void testParseHintsXSDSelection() {
        File file = BaseTest.getResourceAsFile(this, "hints_invalid.xml");
        HintParser instance = new HintParser();
        Exception exception = assertThrows(org.owasp.dependencycheck.xml.hints.HintParseException.class, () -> instance.parseHints(file));
        assertTrue(exception.getMessage().contains("Line=7, Column=133: cvc-enumeration-valid: Value 'version' is not facet-valid with respect to enumeration '[vendor, product]'. It must be a value from the enumeration."));

    }

    /**
     * Test of parseHints method, of class HintParser.
     */
    @Test
    void testParseHints_InputStream() throws Exception {
        InputStream ins = BaseTest.getResourceAsStream(this, "hints_12.xml");
        HintParser instance = new HintParser();
        instance.parseHints(ins);
        List<HintRule> hintRules = instance.getHintRules();
        List<VendorDuplicatingHintRule> vendorRules = instance.getVendorDuplicatingHintRules();
        assertEquals(0, vendorRules.size(), "Zero duplicating hints should have been read");
        assertEquals(2, hintRules.size(), "Two hint rules should have been read");

        assertEquals(1, hintRules.get(0).getGivenProduct().size(), "One given product should have been read in hint 0");
        assertEquals(1, hintRules.get(0).getGivenVendor().size(), "One given vendor should have been read in hint 0");
        assertEquals(1, hintRules.get(0).getGivenVersion().size(), "One given version should have been read in hint 0");

        assertEquals(1, hintRules.get(0).getAddProduct().size(), "One add product should have been read in hint 0");
        assertEquals(1, hintRules.get(0).getAddVendor().size(), "One add vendor should have been read in hint 0");
        assertEquals(1, hintRules.get(0).getAddVersion().size(), "One add version should have been read in hint 0");
        assertEquals(0, hintRules.get(0).getRemoveProduct().size(), "Zero remove product should have been read in hint 0");
        assertEquals(0, hintRules.get(0).getRemoveVendor().size(), "Zero remove vendor should have been read in hint 0");
        assertEquals(0, hintRules.get(0).getRemoveVersion().size(), "Zero remove version should have been read in hint 0");

        assertEquals(0, hintRules.get(1).getGivenProduct().size(), "Zero given product should have been read in hint 1");
        assertEquals(0, hintRules.get(1).getGivenVendor().size(), "Zero given vendor should have been read in hint 1");
        assertEquals(1, hintRules.get(1).getGivenVersion().size(), "One given version should have been read in hint 1");

        assertEquals(1, hintRules.get(1).getRemoveProduct().size(), "One remove product should have been read in hint 1");
        assertEquals(1, hintRules.get(1).getRemoveVendor().size(), "One remove vendor should have been read in hint 1");
        assertEquals(1, hintRules.get(1).getRemoveVersion().size(), "One remove version should have been read in hint 1");
        assertEquals(0, hintRules.get(1).getAddProduct().size(), "Zero add product should have been read in hint 1");
        assertEquals(0, hintRules.get(1).getAddVendor().size(), "Zero add vendor should have been read in hint 1");
        assertEquals(0, hintRules.get(1).getAddVersion().size(), "Zero add version should have been read in hint 1");

        assertEquals("add product name", hintRules.get(0).getAddProduct().get(0).getName(), "add product name not found in hint 0");
        assertEquals("add vendor name", hintRules.get(0).getAddVendor().get(0).getName(), "add vendor name not found in hint 0");
        assertEquals("add version name", hintRules.get(0).getAddVersion().get(0).getName(), "add version name not found in hint 0");

        assertEquals("given product name", hintRules.get(0).getGivenProduct().get(0).getName(), "given product name not found in hint 0");
        assertEquals("given vendor name", hintRules.get(0).getGivenVendor().get(0).getName(), "given vendor name not found in hint 0");
        assertEquals("given version name", hintRules.get(0).getGivenVersion().get(0).getName(), "given version name not found in hint 0");

        assertEquals("given version name", hintRules.get(1).getGivenVersion().get(0).getName(), "given version name not found in hint 1");

        assertEquals("remove product name", hintRules.get(1).getRemoveProduct().get(0).getName(), "add product name not found in hint 1");
        assertEquals("remove vendor name", hintRules.get(1).getRemoveVendor().get(0).getName(), "add vendor name not found in hint 1");
        assertEquals("remove version name", hintRules.get(1).getRemoveVersion().get(0).getName(), "add version name not found in hint 1");

    }

    /**
     * Test of parseHints method, of class HintParser.
     */
    @Test
    void testParseHintsWithRegex() throws Exception {
        InputStream ins = BaseTest.getResourceAsStream(this, "hints_13.xml");
        HintParser instance = new HintParser();
        instance.parseHints(ins);
        List<VendorDuplicatingHintRule> vendor = instance.getVendorDuplicatingHintRules();
        List<HintRule> rules = instance.getHintRules();

        assertEquals(0, vendor.size(), "Zero duplicating hints should have been read");
        assertEquals(2, rules.size(), "Two hint rules should have been read");

        assertEquals(1, rules.get(0).getGivenProduct().size(), "One given product should have been read in hint 0");
        assertEquals(1, rules.get(0).getGivenVendor().size(), "One given vendor should have been read in hint 0");
        assertEquals(1, rules.get(0).getGivenVersion().size(), "One given version should have been read in hint 0");

        assertEquals(1, rules.get(0).getAddProduct().size(), "One add product should have been read in hint 0");
        assertEquals(1, rules.get(0).getAddVendor().size(), "One add vendor should have been read in hint 0");
        assertEquals(1, rules.get(0).getAddVersion().size(), "One add version should have been read in hint 0");
        assertEquals(0, rules.get(0).getRemoveProduct().size(), "Zero remove product should have been read in hint 0");
        assertEquals(0, rules.get(0).getRemoveVendor().size(), "Zero remove vendor should have been read in hint 0");
        assertEquals(0, rules.get(0).getRemoveVersion().size(), "Zero remove version should have been read in hint 0");

        assertEquals(0, rules.get(1).getGivenProduct().size(), "Zero given product should have been read in hint 1");
        assertEquals(0, rules.get(1).getGivenVendor().size(), "Zero given vendor should have been read in hint 1");
        assertEquals(1, rules.get(1).getGivenVersion().size(), "One given version should have been read in hint 1");

        assertEquals(1, rules.get(1).getRemoveProduct().size(), "One remove product should have been read in hint 1");
        assertEquals(1, rules.get(1).getRemoveVendor().size(), "One remove vendor should have been read in hint 1");
        assertEquals(1, rules.get(1).getRemoveVersion().size(), "One remove version should have been read in hint 1");
        assertEquals(0, rules.get(1).getAddProduct().size(), "Zero add product should have been read in hint 1");
        assertEquals(0, rules.get(1).getAddVendor().size(), "Zero add vendor should have been read in hint 1");
        assertEquals(0, rules.get(1).getAddVersion().size(), "Zero add version should have been read in hint 1");

        assertEquals("add product name", rules.get(0).getAddProduct().get(0).getName(), "add product name not found in hint 0");
        assertEquals("add vendor name", rules.get(0).getAddVendor().get(0).getName(), "add vendor name not found in hint 0");
        assertEquals("add version name", rules.get(0).getAddVersion().get(0).getName(), "add version name not found in hint 0");

        assertEquals("given product name", rules.get(0).getGivenProduct().get(0).getName(), "given product name not found in hint 0");
        assertTrue(rules.get(0).getGivenProduct().get(0).isRegex(), "value not registered to be a regex for given product in hint 0");
        assertEquals("given vendor name", rules.get(0).getGivenVendor().get(0).getName(), "given vendor name not found in hint 0");
        assertTrue(rules.get(0).getGivenVendor().get(0).isRegex(), "value not registered to be a regex for given vendor in hint 0");
        assertEquals("given version name", rules.get(0).getGivenVersion().get(0).getName(), "given version name not found in hint 0");
        assertFalse(rules.get(0).getGivenVersion().get(0).isRegex(), "value not registered to not be a regex for given version in hint 0");

        assertEquals("given version name", rules.get(1).getGivenVersion().get(0).getName(), "given version name not found in hint 1");
        assertFalse(rules.get(1).getRemoveProduct().get(0).isRegex(), "value not registered to not be a regex by default for given version in hint 1");

        assertEquals("remove product name", rules.get(1).getRemoveProduct().get(0).getName(), "remove product name not found in hint 1");
        assertFalse(rules.get(1).getRemoveProduct().get(0).isRegex(), "value not registered to not be a regex for product removal in hint 1");
        assertEquals("remove vendor name", rules.get(1).getRemoveVendor().get(0).getName(), "remove vendor name not found in hint 1");
        assertFalse(rules.get(1).getRemoveVendor().get(0).isRegex(), "value not registered to not be a regex for vendor removal in hint 1");
        assertEquals("remove version name", rules.get(1).getRemoveVersion().get(0).getName(), "remove version name not found in hint 1");
        assertFalse(rules.get(1).getRemoveVersion().get(0).isRegex(), "value not defaulted to not be a regex for vendor removal in hint 1");

    }
}
