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
package org.owasp.dependencycheck.data.nvdcve;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.data.update.cpe.CpePlus;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeBuilder;
import us.springett.parsers.cpe.values.LogicalValue;
import us.springett.parsers.cpe.values.Part;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class CveDBIT extends BaseDBTestCase {

    private CveDB instance = null;

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        instance = new CveDB(getSettings());
        instance.open();
    }

    @AfterEach
    @Override
    public void tearDown() throws Exception {
        instance.close();
        super.tearDown();
    }


    /**
     * Test of getCPEs method, of class CveDB.
     */
    @Test
    void testGetCPEs() {
        String vendor = "apache";
        String product = "struts";
        Set<CpePlus> result = instance.getCPEs(vendor, product);
        assertTrue(result.size() > 5);
    }

    /**
     * Test of getVulnerability method, of class CveDB.
     */
    @Test
    void testgetVulnerability() {
        Vulnerability result = instance.getVulnerability("CVE-2014-0094");
        assertTrue(result.getDescription().startsWith("The ParametersInterceptor in Apache Struts"));
    }

    /**
     * Test of getVulnerabilities method, of class CveDB.
     */
    @Test
    void testGetVulnerabilities() throws Exception {

        CpeBuilder builder = new CpeBuilder();
        Cpe cpe = builder.part(Part.APPLICATION).vendor("apache").product("struts").version("2.1.2").build();
        List<Vulnerability> results;

        results = instance.getVulnerabilities(cpe);
        assertTrue(results.size() > 5);
        cpe = builder.part(Part.APPLICATION).vendor("apache").product("tomcat").version("6.0.1").build();
        results = instance.getVulnerabilities(cpe);
        assertTrue(results.size() > 1);

        boolean found = false;
        String expected = "CVE-2014-0075";
        for (Vulnerability v : results) {
            if (expected.equals(v.getName())) {
                found = true;
                break;
            }
        }
        assertTrue(found, "Expected " + expected + ", but was not identified");

        found = false;
        expected = "CVE-2014-0096";
        for (Vulnerability v : results) {
            if (expected.equals(v.getName())) {
                found = true;
                break;
            }
        }
        assertTrue(found, "Expected " + expected + ", but was not identified");

        cpe = builder.part(Part.APPLICATION).vendor("jenkins").product("mailer").version("1.13").build();
        results = instance.getVulnerabilities(cpe);
        assertFalse(results.isEmpty());

        found = false;
        expected = "CVE-2017-2651";
        for (Vulnerability v : results) {
            if (expected.equals(v.getName())) {
                found = true;
                break;
            }
        }
        assertTrue(found, "Expected " + expected + ", but was not identified");

        cpe = builder.part(Part.APPLICATION).vendor("fasterxml").product("jackson-databind").version("2.8.1").build();
        results = instance.getVulnerabilities(cpe);
        assertFalse(results.isEmpty());

        found = false;
        expected = "CVE-2017-15095";
        for (Vulnerability v : results) {
            if (expected.equals(v.getName())) {
                found = true;
                break;
            }
        }
        assertTrue(found, "Expected " + expected + ", but was not identified");
    }

    /**
     * Test of getMatchingSoftware method, of class CveDB.
     */
    @Test
    void testGetMatchingSoftware() throws Exception {

        VulnerableSoftwareBuilder vsBuilder = new VulnerableSoftwareBuilder();
        Set<VulnerableSoftware> software = new HashSet<>();
        software.add(vsBuilder.part(Part.APPLICATION).vendor("openssl").product("openssl").version("1.0.1e").build());

        CpeBuilder cpeBuilder = new CpeBuilder();
        Cpe identified = cpeBuilder.part(Part.APPLICATION).vendor("openssl").product("openssl").version("1.0.1o").build();
        VulnerableSoftware results = instance.getMatchingSoftware(identified, software);
        assertNull(results);
        software.add(vsBuilder.part(Part.APPLICATION).vendor("openssl").product("openssl").version("1.0.1p").build());
        results = instance.getMatchingSoftware(identified, software);
        assertNull(results);

        software.add(vsBuilder.part(Part.APPLICATION).vendor("openssl").product("openssl").version("1.0.1p")
                .versionStartIncluding("1.0.0").versionEndExcluding("1.0.1p").build());
        results = instance.getMatchingSoftware(identified, software);
        assertNotNull(results);
        assertEquals("cpe:/a:openssl:openssl:1.0.1p", results.toCpe22Uri());

        software.clear();

        software.add(vsBuilder.part(Part.APPLICATION).vendor("springsource").product("spring_framework").version("3.2.5").build());
        software.add(vsBuilder.part(Part.APPLICATION).vendor("springsource").product("spring_framework").version("3.2.6").build());
        software.add(vsBuilder.part(Part.APPLICATION).vendor("springsource").product("spring_framework").version("3.2.7")
                .versionStartIncluding("3.0.0").versionEndIncluding("3.2.7").build());

        software.add(vsBuilder.part(Part.APPLICATION).vendor("springsource").product("spring_framework").version("4.0.1")
                .versionStartIncluding("4.0.0").versionEndIncluding("4.0.1").build());
        software.add(vsBuilder.part(Part.APPLICATION).vendor("springsource").product("spring_framework").version("4.0.0").update("m1").build());
        software.add(vsBuilder.part(Part.APPLICATION).vendor("springsource").product("spring_framework").version("4.0.0").update("m2").build());
        software.add(vsBuilder.part(Part.APPLICATION).vendor("springsource").product("spring_framework").version("4.0.0").update("rc1").build());

        identified = cpeBuilder.part(Part.APPLICATION).vendor("springsource").product("spring_framework").version("3.2.2").build();
        results = instance.getMatchingSoftware(identified, software);
        assertEquals("cpe:/a:springsource:spring_framework:3.2.7", results.toCpe22Uri());

        identified = cpeBuilder.part(Part.APPLICATION).vendor("springsource").product("spring_framework").version("3.2.12").build();
        results = instance.getMatchingSoftware(identified, software);
        assertNull(results);

        identified = cpeBuilder.part(Part.APPLICATION).vendor("springsource").product("spring_framework").version("4.0.0").build();
        results = instance.getMatchingSoftware(identified, software);
        assertEquals("cpe:/a:springsource:spring_framework:4.0.1", results.toCpe22Uri());

        identified = cpeBuilder.part(Part.APPLICATION).vendor("springsource").product("spring_framework").version("4.1.0").build();
        results = instance.getMatchingSoftware(identified, software);
        assertNull(results);

        software.clear();

        software.add(vsBuilder.part(Part.APPLICATION).vendor("springsource").product("spring_framework").version(LogicalValue.NA).build());
        identified = cpeBuilder.part(Part.APPLICATION).vendor("springsource").product("spring_framework").version("1.6.3").build();
        results = instance.getMatchingSoftware(identified, software);
        assertNull(results);

        software.clear();
        software.add(vsBuilder.part(Part.APPLICATION).vendor("eclipse").product("jetty").update("20170531").versionEndIncluding("9.5.6").build());
        identified = cpeBuilder.part(Part.APPLICATION).vendor("eclipse").product("jetty").version("9.0.0").update("20170532").build();
        results = instance.getMatchingSoftware(identified, software);
        assertNull(results);
        identified = cpeBuilder.part(Part.APPLICATION).vendor("eclipse").product("jetty").version("9.0.0").update("20170531").build();
        results = instance.getMatchingSoftware(identified, software);
        assertEquals("cpe:/a:eclipse:jetty::20170531", results.toCpe22Uri());

        software.clear();
        software.add(vsBuilder.part(Part.APPLICATION).vendor("jenkins").product("mailer").versionEndExcluding("1.20").targetSw("jenkins").build());
        identified = cpeBuilder.part(Part.APPLICATION).vendor("jenkins").product("mailer").version("1.13").build();
        results = instance.getMatchingSoftware(identified, software);
        assertEquals("cpe:/a:jenkins:mailer:::~~~jenkins~~", results.toCpe22Uri());
    }
}
