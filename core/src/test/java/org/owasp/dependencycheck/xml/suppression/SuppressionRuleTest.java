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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.suppression;

import com.github.packageurl.MalformedPackageURLException;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.CvssUtil;
import us.springett.parsers.cpe.exceptions.CpeValidationException;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test of the suppression rule.
 *
 * @author Jeremy Long
 */
class SuppressionRuleTest extends BaseTest {

    //<editor-fold defaultstate="collapsed" desc="Stupid tests of properties">
    /**
     * Test of FilePath property, of class SuppressionRule.
     */
    @Test
    void testFilePath() {
        SuppressionRule instance = new SuppressionRule();
        PropertyType expResult = new PropertyType();
        expResult.setValue("test");
        instance.setFilePath(expResult);
        PropertyType result = instance.getFilePath();
        assertEquals(expResult, result);
    }

    /**
     * Test of Sha1 property, of class SuppressionRule.
     */
    @Test
    void testSha1() {
        SuppressionRule instance = new SuppressionRule();
        String expResult = "384FAA82E193D4E4B0546059CA09572654BC3970";
        instance.setSha1(expResult);
        String result = instance.getSha1();
        assertEquals(expResult, result);
    }

    /**
     * Test of Cpe property, of class SuppressionRule.
     */
    @Test
    void testCpe() {
        SuppressionRule instance = new SuppressionRule();
        List<PropertyType> cpe = new ArrayList<>();
        instance.setCpe(cpe);
        assertFalse(instance.hasCpe());
        PropertyType pt = new PropertyType();
        pt.setValue("one");
        instance.addCpe(pt);
        assertTrue(instance.hasCpe());
        List<PropertyType> result = instance.getCpe();
        assertEquals(cpe, result);

    }

    /**
     * Test of CvssBelow property, of class SuppressionRule.
     */
    @Test
    void testGetCvssBelow() {
        SuppressionRule instance = new SuppressionRule();
        List<Double> cvss = new ArrayList<>();
        instance.setCvssBelow(cvss);
        assertFalse(instance.hasCvssBelow());
        instance.addCvssBelow(0.7);
        assertTrue(instance.hasCvssBelow());
        List<Double> result = instance.getCvssBelow();
        assertEquals(cvss, result);
    }

    /**
     * Test of Cwe property, of class SuppressionRule.
     */
    @Test
    void testCwe() {
        SuppressionRule instance = new SuppressionRule();
        List<String> cwe = new ArrayList<>();
        instance.setCwe(cwe);
        assertFalse(instance.hasCwe());
        instance.addCwe("2");
        assertTrue(instance.hasCwe());
        List<String> result = instance.getCwe();
        assertEquals(cwe, result);
    }

    /**
     * Test of Cve property, of class SuppressionRule.
     */
    @Test
    void testCve() {
        SuppressionRule instance = new SuppressionRule();
        List<String> cve = new ArrayList<>();
        instance.setCve(cve);
        assertFalse(instance.hasCve());
        instance.addCve("CVE-2013-1337");
        assertTrue(instance.hasCve());
        List<String> result = instance.getCve();
        assertEquals(cve, result);
    }

    /**
     * Test of base property, of class SuppressionRule.
     */
    @Test
    void testBase() {
        SuppressionRule instance = new SuppressionRule();
        assertFalse(instance.isBase());
        instance.setBase(true);
        assertTrue(instance.isBase());
    }

    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="Ignored duplicate tests, left in, as empty tests, so IDE doesn't re-generate them">
    /**
     * Test of getFilePath method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testGetFilePath() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of setFilePath method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testSetFilePath() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of getSha1 method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testGetSha1() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of setSha1 method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testSetSha1() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of getCpe method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testGetCpe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of setCpe method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testSetCpe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of addCpe method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testAddCpe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of hasCpe method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testHasCpe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of setCvssBelow method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testSetCvssBelow() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of addCvssBelow method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testAddCvssBelow() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of hasCvssBelow method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testHasCvssBelow() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of getCwe method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testGetCwe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of setCwe method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testSetCwe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of addCwe method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testAddCwe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of hasCwe method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testHasCwe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of getCve method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testGetCve() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of setCve method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testSetCve() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of addCve method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testAddCve() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of hasCve method, of class SuppressionRule.
     */
    @Test
    @SuppressWarnings("squid:S2699")
    void testHasCve() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    //</editor-fold>

    /**
     * Test of cpeHasNoVersion method, of class SuppressionRule.
     */
    @Test
    void testCpeHasNoVersion() {
        PropertyType c = new PropertyType();
        c.setValue("cpe:/a:microsoft:.net_framework:4.5");
        SuppressionRule instance = new SuppressionRule();
        assertFalse(instance.cpeHasNoVersion(c));
        c.setValue("cpe:/a:microsoft:.net_framework:");
        assertFalse(instance.cpeHasNoVersion(c));
        c.setValue("cpe:/a:microsoft:.net_framework");
        assertTrue(instance.cpeHasNoVersion(c));
    }

    /**
     * Test of identifierMatches method, of class SuppressionRule.
     */
    @Test
    void testCpeMatches() throws CpeValidationException, MalformedPackageURLException {
        CpeIdentifier identifier = new CpeIdentifier("microsoft", ".net_framework", "4.5", Confidence.HIGHEST);

        PropertyType cpe = new PropertyType();
        cpe.setValue("cpe:/a:microsoft:.net_framework:4.5");

        SuppressionRule instance = new SuppressionRule();
        boolean expResult = true;
        boolean result = instance.identifierMatches(cpe, identifier);
        assertEquals(expResult, result);

        cpe.setValue("cpe:/a:microsoft:.net_framework:4.0");
        expResult = false;
        result = instance.identifierMatches(cpe, identifier);
        assertEquals(expResult, result);

        cpe.setValue("CPE:/a:microsoft:.net_framework:4.5");
        cpe.setCaseSensitive(true);
        expResult = false;
        result = instance.identifierMatches(cpe, identifier);
        assertEquals(expResult, result);

        cpe.setValue("cpe:/a:microsoft:.net_framework");
        cpe.setCaseSensitive(false);
        expResult = true;
        result = instance.identifierMatches(cpe, identifier);
        assertEquals(expResult, result);

        cpe.setValue("cpe:/a:microsoft:.*");
        cpe.setRegex(true);
        expResult = true;
        result = instance.identifierMatches(cpe, identifier);
        assertEquals(expResult, result);

        cpe.setValue("CPE:/a:microsoft:.*");
        cpe.setRegex(true);
        cpe.setCaseSensitive(true);
        expResult = false;
        result = instance.identifierMatches(cpe, identifier);
        assertEquals(expResult, result);

        cpe.setValue("cpe:/a:apache:.*");
        cpe.setRegex(true);
        cpe.setCaseSensitive(false);
        expResult = false;
        result = instance.identifierMatches(cpe, identifier);
        assertEquals(expResult, result);

        identifier = new CpeIdentifier("apache", "tomcat", "7.0", Confidence.HIGH);
        cpe.setValue("cpe:/a:apache:tomcat");
        cpe.setRegex(false);
        cpe.setCaseSensitive(false);
        expResult = true;
        result = instance.identifierMatches(cpe, identifier);
        assertEquals(expResult, result);

        PurlIdentifier pid = new PurlIdentifier("maven", "org.springframework", "spring-core", "2.5.5", Confidence.HIGH);
        cpe.setValue("org.springframework:spring-core:2.5.5");
        cpe.setRegex(false);
        cpe.setCaseSensitive(false);
        expResult = true;
        result = instance.identifierMatches(cpe, pid);
        assertEquals(expResult, result);

        cpe.setValue("org\\.springframework\\.security:spring.*");
        cpe.setRegex(true);
        cpe.setCaseSensitive(false);
        expResult = false;
        result = instance.identifierMatches(cpe, pid);
        assertEquals(expResult, result);
    }

    /**
     * Test of process method, of class SuppressionRule.
     */
    @Test
    void testProcess() throws CpeValidationException {
        //File struts = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        File struts = BaseTest.getResourceAsFile(this, "struts2-core-2.1.2.jar");
        Dependency dependency = new Dependency(struts);
        CpeIdentifier cpeId = new CpeIdentifier("microsoft", ".net_framework", "4.5", Confidence.HIGH);
        dependency.addVulnerableSoftwareIdentifier(cpeId);
        String sha1 = dependency.getSha1sum();
        dependency.setSha1sum("384FAA82E193D4E4B0546059CA09572654BC3970");
        Vulnerability v = createVulnerability();
        dependency.addVulnerability(v);

        //cwe
        SuppressionRule instance = new SuppressionRule();
        instance.setSha1(sha1);
        instance.addCwe("287");
        instance.process(dependency);
        assertEquals(1, dependency.getVulnerabilities().size());
        dependency.setSha1sum(sha1);
        instance.process(dependency);
        assertTrue(dependency.getVulnerabilities().isEmpty());
        assertEquals(1, dependency.getSuppressedVulnerabilities().size());

        //cvss
        dependency.addVulnerability(v);
        instance = new SuppressionRule();
        instance.addCvssBelow(5.0);
        instance.process(dependency);
        assertEquals(1, dependency.getVulnerabilities().size());
        instance.addCvssBelow(8.0);
        instance.process(dependency);
        assertTrue(dependency.getVulnerabilities().isEmpty());
        assertEquals(1, dependency.getSuppressedVulnerabilities().size());

        //cve
        dependency.addVulnerability(v);
        instance = new SuppressionRule();
        instance.addCve("CVE-2012-1337");
        instance.process(dependency);
        assertEquals(1, dependency.getVulnerabilities().size());
        instance.addCve("CVE-2013-1337");
        instance.process(dependency);
        assertTrue(dependency.getVulnerabilities().isEmpty());
        assertEquals(1, dependency.getSuppressedVulnerabilities().size());

        //cpe
        instance = new SuppressionRule();
        PropertyType pt = new PropertyType();
        pt.setValue("cpe:/a:microsoft:.net_framework:4.0");
        instance.addCpe(pt);
        instance.process(dependency);
        assertEquals(1, dependency.getVulnerableSoftwareIdentifiers().size());
        pt = new PropertyType();
        pt.setValue("cpe:/a:microsoft:.net_framework:4.5");
        instance.addCpe(pt);
        pt = new PropertyType();
        pt.setValue(".*");
        pt.setRegex(true);
        instance.setFilePath(pt);
        instance.process(dependency);
        assertTrue(dependency.getVulnerableSoftwareIdentifiers().isEmpty());
        assertEquals(1, dependency.getSuppressedIdentifiers().size());

        instance = new SuppressionRule();

        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("microsoft", ".net_framework", "4.0", Confidence.HIGH));
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("microsoft", ".net_framework", "4.5", Confidence.HIGH));
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("microsoft", ".net_framework", "5.0", Confidence.HIGH));
        pt = new PropertyType();
        pt.setValue("cpe:/a:microsoft:.net_framework");
        instance.addCpe(pt);
        instance.setBase(true);
        assertEquals(3, dependency.getVulnerableSoftwareIdentifiers().size());
        assertEquals(1, dependency.getSuppressedIdentifiers().size());
        instance.process(dependency);
        assertTrue(dependency.getVulnerableSoftwareIdentifiers().isEmpty());
        assertEquals(1, dependency.getSuppressedIdentifiers().size());
    }

    /**
     * Test of process method, of class SuppressionRule.
     */
    @Test
    void testProcessGAV() throws CpeValidationException, MalformedPackageURLException {
        //File spring = new File(this.getClass().getClassLoader().getResource("spring-security-web-3.0.0.RELEASE.jar").getPath());
        File spring = BaseTest.getResourceAsFile(this, "spring-security-web-3.0.0.RELEASE.jar");
        Dependency dependency = new Dependency(spring);
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("vmware", "springsource_spring_framework", "3.0.0", Confidence.HIGH));
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("springsource", "spring_framework", "3.0.0", Confidence.HIGH));
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("mod_security", "mod_security", "3.0.0", Confidence.HIGH));
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("vmware", "springsource_spring_security", "3.0.0", Confidence.HIGH));
        dependency.addSoftwareIdentifier(new PurlIdentifier("maven", "org.springframework.security", "spring-security-web", "3.0.0.RELEASE", Confidence.HIGH));

        //cpe
        SuppressionRule instance = new SuppressionRule();
        PropertyType pt = new PropertyType();

        pt.setValue("org\\.springframework\\.security:spring.*");
        pt.setRegex(true);
        pt.setCaseSensitive(false);
        instance.setGav(pt);

        pt = new PropertyType();
        pt.setValue("cpe:/a:mod_security:mod_security");
        instance.addCpe(pt);
        pt = new PropertyType();
        pt.setValue("cpe:/a:springsource:spring_framework");
        instance.addCpe(pt);
        pt = new PropertyType();
        pt.setValue("cpe:/a:vmware:springsource_spring_framework");
        instance.addCpe(pt);

        instance.process(dependency);
        assertEquals(1, dependency.getVulnerableSoftwareIdentifiers().size());

    }

    @Test
    void testProcessVulnerabilityNames() throws CpeValidationException, MalformedPackageURLException {
        File spring = BaseTest.getResourceAsFile(this, "spring-security-web-3.0.0.RELEASE.jar");
        Dependency dependency = new Dependency(spring);
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("vmware", "springsource_spring_security", "3.0.0", Confidence.HIGH));
        dependency.addSoftwareIdentifier(new PurlIdentifier("maven", "org.springframework.security", "spring-security-web", "3.0.0.RELEASE", Confidence.HIGH));

        dependency.addVulnerability(createVulnerability());
        SuppressionRule instance = new SuppressionRule();
        //gav
        PropertyType pt = new PropertyType();
        pt.setValue("pkg:maven/org.springframework.security/spring-security-web@3.0.0.RELEASE");
        pt.setRegex(false);
        pt.setCaseSensitive(false);
        instance.setPackageUrl(pt);

        pt = new PropertyType();
        pt.setValue("CVE-2013-1338");
        instance.addVulnerabilityName(pt);

        instance.process(dependency);
        assertEquals(1, dependency.getVulnerabilities().size());
        assertEquals(0, dependency.getSuppressedVulnerabilities().size());


        pt = new PropertyType();
        pt.setValue("CVE-2013-1337");
        instance.addVulnerabilityName(pt);

        instance.process(dependency);
        assertEquals(0, dependency.getVulnerabilities().size());
        assertEquals(1, dependency.getSuppressedVulnerabilities().size());
    }

    private Vulnerability createVulnerability() {
        Vulnerability v = new Vulnerability();
        v.addCwe("CWE-287 Improper Authentication");
        v.setName("CVE-2013-1337");

        CvssV2 cvss = CvssUtil.vectorToCvssV2("/AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5);
        v.setCvssV2(cvss);
        return v;
    }
}
