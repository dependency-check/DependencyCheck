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
 * Copyright (c) 2026 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.processing;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;

import java.io.InputStream;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link GovulncheckProcessor}.
 *
 * @author Srinivas Chippagiri
 */
class GovulncheckProcessorTest extends BaseTest {

    /**
     * Two advisories affecting the same module/version must both be reported.
     * The virtual dependencies created for them are indistinguishable to
     * {@link Engine#addDependency(Dependency)}, so the vulnerabilities have to be
     * aggregated onto a single dependency; adding them separately silently drops
     * all but the first advisory.
     */
    @Test
    void testAdvisoriesAreAggregatedPerModule() throws Exception {
        final Dependency goDependency = new Dependency(BaseTest.getResourceAsFile(this, "golang/vulncheck/go.mod"));
        try (Engine engine = new Engine(Engine.Mode.EVIDENCE_COLLECTION, getSettings())) {
            try (InputStream in = BaseTest.getResourceAsStream(this, "golang/govulncheck-multi-module.json");
                    GovulncheckProcessor processor = new GovulncheckProcessor(goDependency, engine)) {
                processor.setInput(in);
                processor.run();
            }

            final Dependency[] dependencies = engine.getDependencies();
            // one dependency per vulnerable module: golang.org/x/net and stdlib
            assertEquals(2, dependencies.length);

            final Dependency net = findByName(dependencies, "golang.org/x/net");
            assertNotNull(net, "expected a dependency for golang.org/x/net");
            assertTrue(net.isVirtual());
            assertEquals("0.1.0", net.getVersion());
            final Set<String> names = net.getVulnerabilities().stream()
                    .map(Vulnerability::getName)
                    .collect(Collectors.toSet());
            assertEquals(Set.of("GO-2022-0969", "GO-2023-1988"), names);

            final Dependency stdlib = findByName(dependencies, "stdlib");
            assertNotNull(stdlib, "expected a dependency for the standard library");
            assertEquals("go1.19.3", stdlib.getVersion());
            assertEquals(1, stdlib.getVulnerabilities().size());
        }
    }

    private Dependency findByName(Dependency[] dependencies, String name) {
        for (Dependency d : dependencies) {
            if (name.equals(d.getName())) {
                return d;
            }
        }
        return null;
    }
}
