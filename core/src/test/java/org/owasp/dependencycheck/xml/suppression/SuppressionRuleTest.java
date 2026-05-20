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
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.CvssUtil;
import us.springett.parsers.cpe.CpeParser;
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
        PropertyType expResult = PropertyType.of("test");
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
        PropertyType pt = PropertyType.of("one");
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

    /**
     * Test of identifierMatches method, of class SuppressionRule.
     */
    @Test
    void testCpeMatches() throws Exception {
        Identifier identifier = new CpeIdentifier("microsoft", ".net_framework", "4.5", Confidence.HIGHEST);

        SuppressionRule instance = new SuppressionRule();
        boolean expResult = true;
        boolean result = instance.identifierMatches(PropertyType.of("cpe:/a:microsoft:.net_framework:4.5"), identifier);
        assertEquals(expResult, result);

        expResult = false;
        result = instance.identifierMatches(PropertyType.of("cpe:/a:microsoft:.net_framework:4.0"), identifier);
        assertEquals(expResult, result);

        expResult = false;
        result = instance.identifierMatches(PropertyType.caseSensitive("CPE:/a:microsoft:.net_framework:4.5"), identifier);
        assertEquals(expResult, result);

        expResult = true;
        result = instance.identifierMatches(PropertyType.of("cpe:/a:microsoft:.net_framework"), identifier);
        assertEquals(expResult, result);

        expResult = true;
        result = instance.identifierMatches(PropertyType.regex("cpe:/a:microsoft:.*"), identifier);
        assertEquals(expResult, result);

        expResult = false;
        result = instance.identifierMatches(PropertyType.regexCaseSensitive("CPE:/a:microsoft:.*"), identifier);
        assertEquals(expResult, result);

        expResult = false;
        result = instance.identifierMatches(PropertyType.regex("cpe:/a:apache:.*"), identifier);
        assertEquals(expResult, result);

        identifier = new CpeIdentifier("apache", "tomcat", "7.0", Confidence.HIGH);
        expResult = true;
        result = instance.identifierMatches(PropertyType.of("cpe:/a:apache:tomcat"), identifier);
        assertEquals(expResult, result);

        identifier = new CpeIdentifier(CpeParser.parse("cpe:/a:apache:tomcat_subproduct"), Confidence.HIGH);
        expResult = false;
        result = instance.identifierMatches(PropertyType.of("cpe:/a:apache:tomcat:"), identifier);
        assertEquals(expResult, result);

        identifier = new CpeIdentifier(CpeParser.parse("cpe:/a:apache:tomcat"), Confidence.HIGH);
        expResult = true;
        result = instance.identifierMatches(PropertyType.of("cpe:/a:apache:tomcat:"), identifier);
        assertEquals(expResult, result);
    }

    @Test
    void testGavMatches() throws Exception {
        SuppressionRule instance = new SuppressionRule();

        PurlIdentifier id = new PurlIdentifier("maven", "org.springframework", "spring-core", "2.5.5", Confidence.HIGH);
        PropertyType gav = PropertyType.of("org.springframework:spring-core:2.5.5");
        assertEquals(true, instance.identifierMatches(gav, id), "gav should match purl");

        gav = PropertyType.regex("org\\.springframework\\.security:spring.*");
        assertEquals(false, instance.identifierMatches(gav, id), "gav should match purl by regex");
    }

    /**
     * Test of process method, of class SuppressionRule.
     */
    @Test
    void testProcess() throws CpeValidationException {
        File struts = BaseTest.getResourceAsFile(this, "maven-lib/struts2-core-2.1.2.jar");
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
        instance.addCpe(PropertyType.of("cpe:/a:microsoft:.net_framework:4.0"));
        instance.process(dependency);
        assertEquals(1, dependency.getVulnerableSoftwareIdentifiers().size());
        instance.addCpe(PropertyType.of("cpe:/a:microsoft:.net_framework:4.5"));
        instance.setFilePath(PropertyType.regex(".*"));
        instance.process(dependency);
        assertTrue(dependency.getVulnerableSoftwareIdentifiers().isEmpty());
        assertEquals(1, dependency.getSuppressedIdentifiers().size());

        instance = new SuppressionRule();

        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("microsoft", ".net_framework", "4.0", Confidence.HIGH));
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("microsoft", ".net_framework", "4.5", Confidence.HIGH));
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("microsoft", ".net_framework", "5.0", Confidence.HIGH));
        instance.addCpe(PropertyType.of("cpe:/a:microsoft:.net_framework"));
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
        File spring = BaseTest.getResourceAsFile(this, "maven-lib/spring-security-web-3.0.0.RELEASE.jar");
        Dependency dependency = new Dependency(spring);
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("vmware", "springsource_spring_framework", "3.0.0", Confidence.HIGH));
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("springsource", "spring_framework", "3.0.0", Confidence.HIGH));
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("mod_security", "mod_security", "3.0.0", Confidence.HIGH));
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("vmware", "springsource_spring_security", "3.0.0", Confidence.HIGH));
        dependency.addSoftwareIdentifier(new PurlIdentifier("maven", "org.springframework.security", "spring-security-web", "3.0.0.RELEASE", Confidence.HIGH));

        //cpe
        SuppressionRule instance = new SuppressionRule();

        instance.setGav(PropertyType.regex("org\\.springframework\\.security:spring.*"));
        instance.addCpe(PropertyType.of("cpe:/a:mod_security:mod_security"));
        instance.addCpe(PropertyType.of("cpe:/a:springsource:spring_framework"));
        instance.addCpe(PropertyType.of("cpe:/a:vmware:springsource_spring_framework"));

        instance.process(dependency);
        assertEquals(1, dependency.getVulnerableSoftwareIdentifiers().size());

    }

    @Test
    void testProcessVulnerabilityNames() throws CpeValidationException, MalformedPackageURLException {
        File spring = BaseTest.getResourceAsFile(this, "maven-lib/spring-security-web-3.0.0.RELEASE.jar");
        Dependency dependency = new Dependency(spring);
        dependency.addVulnerableSoftwareIdentifier(new CpeIdentifier("vmware", "springsource_spring_security", "3.0.0", Confidence.HIGH));
        dependency.addSoftwareIdentifier(new PurlIdentifier("maven", "org.springframework.security", "spring-security-web", "3.0.0.RELEASE", Confidence.HIGH));

        dependency.addVulnerability(createVulnerability());
        SuppressionRule instance = new SuppressionRule();
        instance.setPackageUrl(PropertyType.of("pkg:maven/org.springframework.security/spring-security-web@3.0.0.RELEASE"));
        instance.addVulnerabilityName(PropertyType.of("CVE-2013-1338"));

        instance.process(dependency);
        assertEquals(1, dependency.getVulnerabilities().size());
        assertEquals(0, dependency.getSuppressedVulnerabilities().size());

        instance.addVulnerabilityName(PropertyType.of("CVE-2013-1337"));

        instance.process(dependency);
        assertEquals(0, dependency.getVulnerabilities().size());
        assertEquals(1, dependency.getSuppressedVulnerabilities().size());
    }

    @ParameterizedTest
    @CsvSource(
            value = {
                    // vuln has cvss cvssV2=6.0, cvssV3=8.0, cvssV4 is not set
                    // cvssV2Below, cvssV3Below, isSuppressed
                    "   5.0,  7.0,  false",
                    "   7.0,  7.0,  false",
                    "  null,  7.0,  false",
                    "   5.0,  9.0,  false",
                    "   7.0,  9.0,  true",
                    "  null,  9.0,  true",
                    "   5.0, null,  false",
                    "   7.0, null,  true",
                    "  null, null,  false",

                    "   6.0,  8.0,  false", // cvssVnBelows are exclusive
            },
            nullValues = "null")
    void testVersionSpecificThresholding(Double cvssV2Below, Double cvssV3Below, boolean isSuppressed) {
        Dependency dependency = createDependencyWithDifferentScores();
        SuppressionRule rule = new SuppressionRule();

        if (cvssV2Below != null) {
            rule.addCvssV2Below(cvssV2Below);
        }
        if (cvssV3Below != null) {
            rule.addCvssV3Below(cvssV3Below);
        }
        rule.process(dependency);

        assertEquals(isSuppressed ? 0 : 1, dependency.getVulnerabilities().size(),
                String.format("cvssV2Below=%s, cvssV3Below=%s: expecting vulnerability to be %s",
                        cvssV2Below == null ? "not set" : String.format("%.1f", cvssV2Below),
                        cvssV3Below == null ? "not set" : String.format("%.1f", cvssV3Below),
                        isSuppressed ? "suppressed" : "not suppressed")
        );
        assertEquals(isSuppressed ? 1 : 0, dependency.getSuppressedVulnerabilities().size());
    }


    @Test
    void testMismatchOfThresholdAndAvailableCVEVersion() {
        // vuln with only a cvss v2 score
        File spring = BaseTest.getResourceAsFile(this, "maven-lib/spring-security-web-3.0.0.RELEASE.jar");
        Dependency dependency = new Dependency(spring);
        Vulnerability v = new Vulnerability();
        CvssV2 cvss = CvssUtil.vectorToCvssV2("/AV:N/AC:L/Au:N/C:P/I:P/A:P", 6.0);
        v.setCvssV2(cvss);
        dependency.addVulnerability(v);

        // rule with only a V3 threshold
        SuppressionRule rule = new SuppressionRule();
        rule.addCvssV3Below(7.0);

        assertEquals(1, dependency.getVulnerabilities().size(),
                "Since threshold and score versions are different versions the vuln should not be suppressed");
    }

    @Test
    void testThresholdAreExclusive() {
        Dependency dependency = createDependencyWithDifferentScores();
        SuppressionRule rule = new SuppressionRule();
        rule.addCvssBelow(6.0);
        rule.process(dependency);

        assertEquals(1, dependency.getVulnerabilities().size(),
                "A cvssBelow of 6.0 will not suppress a vulnerability with a score of 6.0");
        assertEquals(0, dependency.getSuppressedVulnerabilities().size());
    }

    @Test
    void testThresholdHighestIsUseIfMultipleBelows() {
        Dependency dependency = createDependencyWithDifferentScores();
        SuppressionRule rule = new SuppressionRule();
        rule.addCvssBelow(5.0);
        rule.addCvssBelow(7.0);
        rule.process(dependency);

        assertEquals(0, dependency.getVulnerabilities().size(),
                "A cvssBelow of 5.0 and 7.0 will suppress a vulnerability with a score of 6.0");
        assertEquals(1, dependency.getSuppressedVulnerabilities().size());
    }

    @Test
    void testThresholdHighestIsUseIfMultipleVersionedBelows() {
        Dependency dependency = createDependencyWithDifferentScores();
        SuppressionRule rule = new SuppressionRule();
        rule.addCvssV2Below(5.0);
        rule.addCvssV2Below(7.0);
        rule.process(dependency);

        assertEquals(0, dependency.getVulnerabilities().size(),
                "A cvssBelow of 5.0 and 7.0 will suppress a vulnerability with a score of 6.0");
        assertEquals(1, dependency.getSuppressedVulnerabilities().size());
    }

    private Dependency createDependencyWithDifferentScores() {
        File spring = BaseTest.getResourceAsFile(this, "maven-lib/spring-security-web-3.0.0.RELEASE.jar");
        Dependency dependency = new Dependency(spring);
        Vulnerability v = new Vulnerability();
        CvssV2 cvss = CvssUtil.vectorToCvssV2("/AV:N/AC:L/Au:N/C:P/I:P/A:P", 6.0);
        v.setCvssV2(cvss);
        CvssV3 cvss3 = CvssUtil.vectorToCvssV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.0);
        v.setCvssV3(cvss3);
        dependency.addVulnerability(v);
        return dependency;
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
