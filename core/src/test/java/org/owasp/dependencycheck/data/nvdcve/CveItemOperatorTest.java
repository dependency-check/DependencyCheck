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
import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jeremy
 */
public class CveItemOperatorTest {

    /**
     * Test of testCveCpeStartWithFilter method, of class CveItemOperator.
     */
    @Test
    public void testTestCveCpeStartWithFilter() {

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
        List<Node> nodes = new ArrayList<>();
        nodes.add(null);
        nodes.add(first);
        nodes.add(second);
        
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

}
