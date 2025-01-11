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
 * Copyright (c) 2018 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.agent;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.FileUtils;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.owasp.dependencycheck.BaseDBTestCase;

public class DependencyCheckScanAgentIT extends BaseDBTestCase {

    private static final File REPORT_DIR = new File("target/test-scan-agent/report");

    @BeforeClass
    public static void beforeClass() {
        if (!REPORT_DIR.exists()) {
            REPORT_DIR.mkdirs();
        }
    }

    @Test
    public void testComponentMetadata() throws Exception {
        List<Dependency> dependencies = new ArrayList<>();
        dependencies.add(createDependency("apache", "tomcat", "5.0.5"));
        DependencyCheckScanAgent scanAgent = createScanAgent();
        scanAgent.setDependencies(dependencies);
        scanAgent.execute();

        Dependency tomcat = scanAgent.getDependencies().get(0);
        Assert.assertTrue(tomcat.getVulnerableSoftwareIdentifiers().size() >= 1);

        // This will change over time
        Assert.assertTrue(tomcat.getVulnerabilities().size() > 5);
    }

    private DependencyCheckScanAgent createScanAgent() {
        final DependencyCheckScanAgent scanAgent = new DependencyCheckScanAgent();
        scanAgent.setApplicationName("Dependency-Track");
        //the following does not work because it will be over-ridden by the system
        //  properties configured during surefire/failsafe
        //scanAgent.setDataDirectory(DATA_DIR.getAbsolutePath());
        scanAgent.setCentralAnalyzerEnabled(false);
        scanAgent.setReportOutputDirectory(REPORT_DIR.getAbsolutePath());
        scanAgent.setReportFormat(ReportGenerator.Format.XML);
        scanAgent.setAutoUpdate(false);
        scanAgent.setUpdateOnly(false);
        return scanAgent;
    }

    private Dependency createDependency(final String vendor, final String name, final String version) {
        final Dependency dependency = new Dependency(new File(FileUtils.getBitBucket()), true);
        dependency.setName(name);
        dependency.setVersion(version);
        if (vendor != null) {
            dependency.addEvidence(EvidenceType.VENDOR, "dependency-track", "vendor", vendor, Confidence.HIGHEST);
            dependency.addVendorWeighting(vendor);
        }
        if (name != null) {
            dependency.addEvidence(EvidenceType.PRODUCT, "dependency-track", "name", name, Confidence.HIGHEST);
            dependency.addEvidence(EvidenceType.VENDOR, "dependency-track", "name", name, Confidence.HIGH);
            dependency.addProductWeighting(name);
        }
        if (version != null) {
            dependency.addEvidence(EvidenceType.VERSION, "dependency-track", "version", version, Confidence.HIGHEST);
        }
        return dependency;
    }
}
