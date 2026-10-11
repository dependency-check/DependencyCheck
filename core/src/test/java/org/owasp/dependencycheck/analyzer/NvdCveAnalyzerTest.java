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
 * Copyright (c) 2026 Akhil CH. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.owasp.dependencycheck.analyzer.NvdCveAnalyzer.ecosystemMatchesTargetSoftware;
import static org.owasp.dependencycheck.analyzer.NvdCveAnalyzer.filterEcosystem;

class NvdCveAnalyzerTest {

    @Test
    void testTargetSoftwareForAnotherRuntimeDoesNotMatch() {
        // CVE-2019-7617 is the Python APM agent, reported on the Java agent (#3876)
        assertFalse(ecosystemMatchesTargetSoftware(Ecosystem.JAVA, "python"));
        // CVE-2020-36448 is the Rust cache crate, reported on cache4k-jvm (#6851)
        assertFalse(ecosystemMatchesTargetSoftware(Ecosystem.JAVA, "rust"));
        assertFalse(ecosystemMatchesTargetSoftware(Ecosystem.PYTHON, "java"));
        assertFalse(ecosystemMatchesTargetSoftware(Ecosystem.DOTNET, "wordpress"));
        assertFalse(ecosystemMatchesTargetSoftware(Ecosystem.GOLANG, "ruby"));
    }

    @Test
    void testTargetSoftwareForTheSameRuntimeMatches() {
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.JAVA, "java"));
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.JAVA, "android"));
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.PYTHON, "python"));
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.PHP, "wordpress"));
    }

    @Test
    void testTargetSoftwareThatNamesNoRuntimeMatches() {
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.JAVA, "*"));
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.JAVA, "-"));
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.JAVA, "linux"));
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.JAVA, "iphone_os"));
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.JAVA, "not_mapped"));
        // JavaScript libraries are bundled in webjars and NuGet packages
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.JAVA, "node.js"));
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.DOTNET, "jquery"));
    }

    @Test
    void testDependenciesOutsideTheRuntimesMatchEverything() {
        assertTrue(ecosystemMatchesTargetSoftware(null, "python"));
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.NATIVE, "python"));
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.JAVASCRIPT, "python"));
    }

    @Test
    void testNodeDependenciesOnlyMatchNodeTargetSoftware() {
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.NODEJS, "node.js"));
        assertTrue(ecosystemMatchesTargetSoftware(Ecosystem.NODEJS, "*"));
        assertFalse(ecosystemMatchesTargetSoftware(Ecosystem.NODEJS, "jquery"));
        assertFalse(ecosystemMatchesTargetSoftware(Ecosystem.NODEJS, "python"));
    }

    @Test
    void testFilterEcosystemDoesNotChangeTheCachedList() throws CpeValidationException {
        VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();
        Vulnerability pythonOnly = new Vulnerability("python-only");
        pythonOnly.addVulnerableSoftware(builder.part(Part.APPLICATION).vendor("elastic").product("apm_agent")
                .targetSw("python").build());
        Vulnerability mixed = new Vulnerability("mixed");
        mixed.addVulnerableSoftware(builder.part(Part.APPLICATION).vendor("elastic").product("apm_agent")
                .targetSw("python").build());
        mixed.addVulnerableSoftware(builder.part(Part.APPLICATION).vendor("elastic").product("apm_agent")
                .targetSw("*").build());
        List<Vulnerability> cached = new ArrayList<>(List.of(pythonOnly, mixed));

        assertEquals(List.of(mixed), filterEcosystem(Ecosystem.JAVA, cached));
        assertEquals(List.of(pythonOnly, mixed), cached);
        assertEquals(2, mixed.getVulnerableSoftware().size());
        assertEquals(cached, filterEcosystem(Ecosystem.PYTHON, cached));
    }
}
