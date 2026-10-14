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
 * Copyright (c) 2024 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;

import io.github.jeremylong.openvulnerability.client.nvd.Config;
import io.github.jeremylong.openvulnerability.client.nvd.CpeMatch;
import io.github.jeremylong.openvulnerability.client.nvd.CveItem;
import io.github.jeremylong.openvulnerability.client.nvd.CveTag;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import io.github.jeremylong.openvulnerability.client.nvd.LangString;
import io.github.jeremylong.openvulnerability.client.nvd.Metrics;
import io.github.jeremylong.openvulnerability.client.nvd.Node;
import io.github.jeremylong.openvulnerability.client.nvd.Reference;
import io.github.jeremylong.openvulnerability.client.nvd.VendorComment;
import io.github.jeremylong.openvulnerability.client.nvd.Weakness;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 *
 * @author jeremy
 */
class CveItemOperatorTest {

    /**
     * Test of testCveCpeStartWithFilter method, of class CveItemOperator.
     */
    @Test
    void testTestCveCpeStartWithFilter() {

        ZonedDateTime published = ZonedDateTime.now();
        ZonedDateTime lastModified = ZonedDateTime.now();
        LocalDate cisaExploitAdd = null;
        LocalDate cisaActionDue = null;
        List<CveTag> cveTags = null;
        List<LangString> descriptions = null;
        List<Reference> references = null;
        Metrics metrics = null;
        List<Weakness> weaknesses = null;
        List<Config> configurations = new ArrayList<>();
        List<CpeMatch> matches = new ArrayList<>();
        matches.add(null);
        Node first = new Node(Node.Operator.OR, null, matches);
        List<CpeMatch> cpeMatch = new ArrayList<>();
        //cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*
        CpeMatch match = new CpeMatch(true, "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", "matchCriteriaId", "versionStartExcluding",
            "versionStartIncluding", "versionEndExcluding", "versionEndIncluding");
        cpeMatch.add(match);
        Node second = new Node(Node.Operator.OR, Boolean.FALSE, cpeMatch);
        Node third = new Node(Node.Operator.OR, null, null);
        List<Node> nodes = new ArrayList<>();
        nodes.add(null);
        nodes.add(first);
        nodes.add(second);
        nodes.add(third);

        Config c = new Config(Config.Operator.AND, null, nodes);
        configurations.add(c);
        List<VendorComment> vendorComments = null;
        CveItem cveItem = new CveItem("id", "sourceIdentifier", "vulnStatus", published, lastModified,
                "evaluatorComment", "evaluatorSolution", "evaluatorImpact", cisaExploitAdd, cisaActionDue,
                "cisaRequiredAction", "cisaVulnerabilityName", cveTags, descriptions, references, metrics,
                weaknesses, configurations, vendorComments);

        DefCveItem cve = new DefCveItem(cveItem);
        CveItemOperator instance = new CveItemOperator("cpe:2.3:o:");
        boolean expResult = true;
        boolean result = instance.testCveCpeStartWithFilter(cve);
        assertEquals(expResult, result);

    }

    @Test
    void testTestCveCpeStartWithFilterForConfigurationWithoutCpeMatches() {
        ZonedDateTime published = ZonedDateTime.now();
        ZonedDateTime lastModified = ZonedDateTime.now();
        LocalDate cisaExploitAdd = null;
        LocalDate cisaActionDue = null;
        List<CveTag> cveTags = null;
        List<LangString> descriptions = null;
        List<Reference> references = null;
        Metrics metrics = null;
        List<Weakness> weaknesses = null;

        Node noCpeMatches = new Node(Node.Operator.OR, null, null);
        Config c = new Config(Config.Operator.AND, null, List.of(noCpeMatches));
        List<VendorComment> vendorComments = null;
        CveItem cveItem = new CveItem("id", "sourceIdentifier", "vulnStatus", published, lastModified,
                "evaluatorComment", "evaluatorSolution", "evaluatorImpact", cisaExploitAdd, cisaActionDue,
                "cisaRequiredAction", "cisaVulnerabilityName", cveTags, descriptions, references, metrics,
                weaknesses, List.of(c), vendorComments);

        DefCveItem cve = new DefCveItem(cveItem);
        CveItemOperator instance = new CveItemOperator("cpe:2.3:o:");
        boolean expResult = false;
        boolean result = instance.testCveCpeStartWithFilter(cve);
        assertEquals(expResult, result);
    }

    /**
     * Pins down the ecosystem stored for each target_sw value. A value that is
     * not mapped keeps the base ecosystem, which is null here.
     */
    @ParameterizedTest
    @CsvSource({
        "asp.net, dotnet", "c#, dotnet", ".net, dotnet", "dotnetnuke, dotnet",
        "android, java", "java, java",
        "c/c++, native", "borland_c++, native", "visual_c++, native", "gnu_c++, native",
        "linux_kernel, native", "linux, native", "unix, native", "suse_linux, native",
        "redhat_enterprise_linux, native", "debian, native",
        "coldfusion, coldfusion",
        "ios, ios", "iphone, ios", "ipad, ios", "iphone_os, ios",
        "jquery, js",
        "node.js, nodejs", "nodejs, nodejs",
        "perl, perl",
        "joomla!, php", "joomla, php", "mybb, php", "simplesamlphp, php", "craft_cms, php",
        "moodle, php", "phpcms, php", "buddypress, php", "typo3, php", "php, php",
        "wordpress, php", "drupal, php", "mediawiki, php", "symfony, php", "openpne, php",
        "vbulletin3, php", "vbulletin4, php",
        "python, python",
        "ruby, ruby",
        "*,", "-,", "rust,", "go,", "golang,", "swift,", "elixir,", "jenkins,", "macos,", "windows,", "c++,"
    })
    void testExtractEcosystemFromTargetSw(String targetSw, String expected) throws CpeValidationException {
        assertEquals(expected, extractEcosystem(null, "vendor", "product", targetSw));
    }

    @Test
    void testExtractEcosystemKeepsTheBaseEcosystem() throws CpeValidationException {
        assertEquals(Ecosystem.JAVA, extractEcosystem(Ecosystem.JAVA, "vendor", "product", "*"));
        assertEquals(Ecosystem.JAVA, extractEcosystem(Ecosystem.JAVA, "vendor", "product", "rust"));
        assertEquals(Ecosystem.PYTHON, extractEcosystem(Ecosystem.JAVA, "vendor", "product", "python"));
    }

    /**
     * Pins down the vendor and product checks that run before target_sw.
     */
    @Test
    void testExtractEcosystemFromVendorAndProduct() throws CpeValidationException {
        assertNull(extractEcosystem(Ecosystem.JAVA, "apache", "zookeeper", "java"));
        assertEquals(Ecosystem.NATIVE, extractEcosystem(Ecosystem.JAVA, "ibm", "java", "*"));
        assertEquals(Ecosystem.NATIVE, extractEcosystem(null, "oracle", "vm", "*"));
    }

    private static String extractEcosystem(String baseEcosystem, String vendor, String product, String targetSw)
            throws CpeValidationException {
        final VulnerableSoftware software = new VulnerableSoftwareBuilder().part(Part.APPLICATION)
                .vendor(vendor).product(product).targetSw(targetSw).build();
        return new CveItemOperator("cpe:2.3:a:").extractEcosystem(baseEcosystem, software);
    }
}
