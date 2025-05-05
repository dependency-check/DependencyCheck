/*
 * This file is part of dependency-check-cofre.
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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.update.RetireJSDataSource;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RetireJsAnalyzerFiltersTest extends BaseDBTestCase {

    /**
     * Test of filters method.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    void testFilters() throws Exception {

        String[] filter = {"jQuery JavaScript Library"};
        getSettings().setArrayIfNotEmpty(Settings.KEYS.ANALYZER_RETIREJS_FILTERS, filter);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_RETIREJS_FILTER_NON_VULNERABLE, true);

        RetireJsAnalyzer analyzer = null;
        try (Engine engine = new Engine(getSettings())) {
            engine.openDatabase(true, true);
            RetireJSDataSource ds = new RetireJSDataSource();
            ds.update(engine);
            analyzer = new RetireJsAnalyzer();
            analyzer.setFilesMatched(true);

            analyzer.initialize(getSettings());
            analyzer.prepare(engine);

            //removed by filter (see setup above)
            File file = BaseTest.getResourceAsFile(this, "javascript/jquery-1.6.2.js");
            List<Dependency> scanned = engine.scan(file);
            assertTrue(scanned == null || scanned.isEmpty());

            //remove non-vulnerable
            file = BaseTest.getResourceAsFile(this, "javascript/custom.js");
            scanned = engine.scan(file);
            assertEquals(1, scanned.size());
            assertEquals(1, engine.getDependencies().length);
            analyzer.analyze(scanned.get(0), engine);
            assertEquals(0, engine.getDependencies().length);

            //kept because it is does not match the filter and is vulnerable
            file = BaseTest.getResourceAsFile(this, "javascript/ember.js");
            scanned = engine.scan(file);
            assertEquals(1, scanned.size());
            assertEquals(1, engine.getDependencies().length);
            analyzer.analyze(scanned.get(0), engine);
            assertEquals(1, engine.getDependencies().length);
        } finally {
            if (analyzer != null) {
                analyzer.close();
            }
        }
    }
}
