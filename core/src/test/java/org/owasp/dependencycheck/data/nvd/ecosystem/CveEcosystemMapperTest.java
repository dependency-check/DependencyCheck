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
 * Copyright (c) 2020 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvd.ecosystem;

import io.github.jeremylong.openvulnerability.client.nvd.Config;
import io.github.jeremylong.openvulnerability.client.nvd.CpeMatch;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;

import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import io.github.jeremylong.openvulnerability.client.nvd.CveItem;
import io.github.jeremylong.openvulnerability.client.nvd.LangString;
import io.github.jeremylong.openvulnerability.client.nvd.Node;

/**
 *
 * @author Jeremy Long
 */
public class CveEcosystemMapperTest {

    /**
     * Test of getEcosystem method, of class CveEcosystemMapper.
     */
    @Test
    public void testGetEcosystem() {
        CveEcosystemMapper mapper = new CveEcosystemMapper();
        String value = "There is a vulnerability in some.java file";
        assertEquals(JarAnalyzer.DEPENDENCY_ECOSYSTEM, mapper.getEcosystem(asCve(value)));
        value = "There is a vulnerability in some file";
        assertNull(mapper.getEcosystem(asCve(value,"cpe:2.3:a:apache:struts:1.2.1:*:*:*:*:*:*:*")));
    }

    private DefCveItem asCve(String description, String... cpe) {

        List<LangString> d = new ArrayList<>();
        LangString str = new LangString("en", description);
        d.add(str);

        List<Config> configurations = new ArrayList<>();
        List<Node> nodes = new ArrayList<>();
        List<CpeMatch> cpeMatch = new ArrayList<>();
        for (String s : cpe) {
            CpeMatch m = new CpeMatch(Boolean.TRUE, s, null, null, null, null, null);
            cpeMatch.add(m);
        }
        Node node = new Node(Node.Operator.OR, Boolean.FALSE, cpeMatch);
        nodes.add(node);
        Config conf = new Config(Config.Operator.AND, Boolean.FALSE, nodes);
        CveItem cveItem = new CveItem(null, null, null, null, null, null, null, null, null, null, null, null, null, d, null, null, null, configurations, null);
        DefCveItem defCveItem = new DefCveItem(cveItem);

        return defCveItem;
    }
}
