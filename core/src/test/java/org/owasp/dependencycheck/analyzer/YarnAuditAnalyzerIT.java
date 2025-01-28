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
 * Copyright (c) 2021 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.Assume;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.InvalidSettingException;

import static org.junit.Assert.assertTrue;

public class YarnAuditAnalyzerIT extends BaseTest {

    @Test
    public void testAnalyzePackageYarnClassic() throws AnalysisException, InitializationException, InvalidSettingException {
        testAnalyzePackageYarn("yarn-classic-audit/yarn.lock");
    }

    @Test
    public void testAnalyzePackageYarnBerry() throws AnalysisException, InitializationException, InvalidSettingException {
        testAnalyzePackageYarn("yarn-berry-audit/yarn.lock");
    }

    private void testAnalyzePackageYarn(String yarnLockFile) throws AnalysisException {
        //Assume.assumeThat(getSettings().getBoolean(Settings.KEYS.ANALYZER_YARN_AUDIT_ENABLED), is(true));
        try (Engine engine = new Engine(getSettings())) {
            var analyzer = new YarnAuditAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, yarnLockFile));
            analyzer.analyze(toScan, engine);
            boolean found = false;
            assertTrue("More then 1 dependency should be identified", 1 < engine.getDependencies().length);
            for (Dependency result : engine.getDependencies()) {
                if ("yarn.lock?uglify-js".equals(result.getFileName())) {
                    found = true;
                    assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("uglify-js"));
                    assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("uglify-js"));
                    assertTrue("Unable to find version 2.4.24: " + result.getEvidence(EvidenceType.VERSION).toString(), result.getEvidence(EvidenceType.VERSION).toString().contains("2.4.24"));
                    assertTrue(result.isVirtual());
                }
            }
            assertTrue("Uglify was not found", found);
        } catch (InitializationException ex) {
            //yarn is not installed - skip the test case.
            Assume.assumeNoException(ex);
        }
    }
}
