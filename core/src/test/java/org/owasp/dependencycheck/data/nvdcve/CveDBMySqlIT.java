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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.update.cpe.CpePlus;
import org.owasp.dependencycheck.dependency.Vulnerability;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeBuilder;
import us.springett.parsers.cpe.values.Part;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class CveDBMySqlIT extends BaseTest {

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
        try {
            String vendor = "apache";
            String product = "struts";
            Set<CpePlus> result = instance.getCPEs(vendor, product);
            assertTrue(result.size() > 5, "Has data been loaded into the MySQL DB? if not consider using the CLI to populate it");
        } catch (Exception ex) {
            System.out.println("Unable to access the My SQL database; verify that the db server is running and that the schema has been generated");
            throw ex;
        }
    }

    /**
     * Test of getVulnerabilities method, of class CveDB.
     */
    @Test
    void testGetVulnerabilities() throws Exception {
        CpeBuilder builder = new CpeBuilder();
        Cpe cpe = builder.part(Part.APPLICATION).vendor("apache").product("struts").version("2.1.2").build();
        try {
            List<Vulnerability> result = instance.getVulnerabilities(cpe);
            assertTrue(result.size() > 5);
        } catch (Exception ex) {
            System.out.println("Unable to access the My SQL database; verify that the db server is running and that the schema has been generated");
            throw ex;
        }
    }
}
