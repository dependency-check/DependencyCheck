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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;

/**
 *
 * @author Jeremy Long
 */
class DependencyBundlingAnalyzerIT extends BaseDBTestCase {

    /**
     * Test of analyze method, of class DependencyBundlingAnalyzer.
     */
    @Test
    void testAnalyze() {
//        Engine engine = null;
//        JarAnalyzer ja = null;
//        FileNameAnalyzer fna = null;
//        CPEAnalyzer cpea = null;
//        DependencyBundlingAnalyzer instance = null;
//        try {
//            //Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
//            Settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
//            //Settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
//            engine = new Engine();
//            engine.doUpdates();
//
//            File file1 = new File("C:\\Users\\jeremy\\Projects\\testCases\\batlik\\app1.war");
//            File file2 = new File("C:\\Users\\jeremy\\Projects\\testCases\\batlik\\app2.war");
//            Dependency dependency1 = new Dependency(file1);
//            Dependency dependency2 = new Dependency(file2);
//            engine.getDependencies().add(dependency1);
//            engine.getDependencies().add(dependency2);
//            ArchiveAnalyzer aa = new ArchiveAnalyzer();
//            aa.setEnabled(true);
//            aa.setFilesMatched(true);
//            aa.initialize();
//            ja = new JarAnalyzer();
//            ja.setFilesMatched(true);
//            ja.setEnabled(true);
//            ja.initialize();
//            fna = new FileNameAnalyzer();
//            fna.initialize();
//            cpea = new CPEAnalyzer();
//            cpea.initialize();
//
//            aa.analyze(dependency1, engine);
//            aa.analyze(dependency2, engine);
//
//            for (Dependency d : engine.getDependencies()) {
//                fna.analyze(d, engine);
//                ja.analyze(d, engine);
//                cpea.analyze(d, engine);
//            }
//
//            instance = new DependencyBundlingAnalyzer();
//            instance.initialize();
//            instance.analyze(null, engine);
//            System.out.println(engine.getDependencies().size());
//            for (Dependency d : engine.getDependencies()) {
//                System.out.println(d.getDisplayFileName());
//            }
//        } finally {
//            if (ja != null) {
//                ja.close();
//            }
//            if (fna != null) {
//                fna.close();
//            }
//            if (cpea != null) {
//                cpea.close();
//            }
//            if (instance != null) {
//                instance.close();
//            }
//            if (engine != null) {
//                engine.cleanup();
//            }
//        }
    }
}
