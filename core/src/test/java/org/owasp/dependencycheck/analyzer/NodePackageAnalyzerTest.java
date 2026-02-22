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
 * Copyright (c) 2015 Institute for Defense Analyses. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Unit tests for NodePackageAnalyzer.
 *
 * @author Dale Visser
 */
class NodePackageAnalyzerTest extends BaseTest {

    /**
     * The analyzer to test.
     */
    private NodePackageAnalyzer analyzer;
    /**
     * A reference to the engine.
     */
    private Engine engine;

    /**
     * Retrieves the node audit analyzer from the engine.
     *
     * @param engine the ODC engine
     * @return returns the node audit analyzer from the engine
     */
    private NodeAuditAnalyzer getNodeAuditAnalyzer(Engine engine) {
        for (Analyzer a : engine.getAnalyzers()) {
            if (a instanceof NodeAuditAnalyzer) {
                return (NodeAuditAnalyzer) a;
            }
        }
        return null;
    }

    /**
     * Retrieves the node package analyzer from the engine.
     *
     * @param engine the ODC engine
     * @return returns the node package analyzer from the engine
     */
    private NodePackageAnalyzer getNodePackageAnalyzer(Engine engine) {
        for (Analyzer a : engine.getAnalyzers()) {
            if (a instanceof NodePackageAnalyzer) {
                return (NodePackageAnalyzer) a;
            }
        }
        return null;
    }

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        if (getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED)) {
            engine = new Engine(this.getSettings());
            NodeAuditAnalyzer auditAnalyzer = getNodeAuditAnalyzer(engine);
            auditAnalyzer.setFilesMatched(true);
            analyzer = getNodePackageAnalyzer(engine);
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            try {
                analyzer.prepare(engine);
            } catch (InitializationException ex) {
                if (!ex.getMessage().startsWith("Missing package.lock or npm-shrinkwrap.lock file")) {
                    throw ex;
                }
            }
        }
    }

    /**
     * Cleanup temp files, close resources, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @AfterEach
    @Override
    public void tearDown() throws Exception {
        if (getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED)) {
            analyzer.close();
            engine.close();
        }
        super.tearDown();

    }

    /**
     * Test of getName method, of class PythonDistributionAnalyzer.
     */
    @Test
    void testGetName() throws InvalidSettingException {
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED));
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED));
        assertThat(analyzer.getName(), is("Node.js Package Analyzer"));
    }

    /**
     * Test of supportsExtension method, of class PythonDistributionAnalyzer.
     */
    @Test
    void testSupportsFiles() throws InvalidSettingException {
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED));
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED));
        assertThat(analyzer.accept(new File("package-lock.json")), is(true));
        assertThat(analyzer.accept(new File("npm-shrinkwrap.json")), is(true));
    }

    /**
     * Test of inspect method, of class PythonDistributionAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testAnalyzeShrinkwrapJson() throws AnalysisException, InvalidSettingException {
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED));
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED));
        final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this,
                "nodejs/npm-shrinkwrap.json"));
        final Dependency toCombine = new Dependency(BaseTest.getResourceAsFile(this,
                "nodejs/node_modules/dns-sync/package.json"));
        engine.addDependency(toScan);
        engine.addDependency(toCombine);
        analyzer.analyze(toScan, engine);
        analyzer.analyze(toCombine, engine);

        testLock();
    }

    private void testLock() {
        final boolean isMac = System.getProperty("os.name").toLowerCase().contains("mac");

        // test some dependencies
        boolean bracesFound = false;
        boolean expandRangeFound = false;

        Dependency result = null;
        for (Dependency dep : engine.getDependencies()) {
            if (!isMac && "fsevents".equals(dep.getName())) {
                fail("fsevents need to be skipped on non mac");
            }

            if ("react-dom".equals(dep.getName())) {
                fail("react-dom need to be skipped because it's an alias");
            }

            if ("braces".equals(dep.getName())) {
                bracesFound = true;
            }

            if ("expand-range".equals(dep.getName())) {
                expandRangeFound = true;
            }

            if ("fake_submodule".equals(dep.getName())) {
                fail("start with file: need to be skipped because it's a local package");
            }

            if ("react-dom".equals(dep.getName())) {
                fail("start with file: need to be skipped because it's a local package");
            }

            if ("dns-sync".equals(dep.getName())) {
                result = dep;
            }
        }

        assertTrue(bracesFound, "need to contain braces");
        //check if dependencies of dependencies are imported
        assertTrue(expandRangeFound, "need to contain expand-range (dependency of braces)");

        final String vendorString = result.getEvidence(EvidenceType.VENDOR).toString();
        assertThat(vendorString, containsString("Sanjeev Koranga"));
        assertThat(vendorString, containsString("dns-sync"));
        assertThat(result.getEvidence(EvidenceType.PRODUCT).toString(), containsString("dns-sync"));
        assertThat(result.getEvidence(EvidenceType.VERSION).toString(), containsString("0.1.3"));
        assertEquals(NodePackageAnalyzer.DEPENDENCY_ECOSYSTEM, result.getEcosystem());
        assertEquals("dns-sync", result.getName());
        assertEquals("0.1.3", result.getVersion());

        // with npm install run on a "non-macOs" system, 90 else
        // dependencies length change often, maybe not a good idea to test the length, check some dependencies instead
        //  assertEquals("Expected 40 dependencies", 40, engine.getDependencies().length);
        // shrinkWrap is not removed because the NodeAudit analyzer is enabled
        //assertFalse(shrinkwrap.equals(engine.getDependencies()[0]));
    }

    /**
     * Test of inspect method, of class PythonDistributionAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testAnalyzePackageJsonWithShrinkwrap() throws AnalysisException, InvalidSettingException {
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED));
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED));
        final Dependency packageJson = new Dependency(BaseTest.getResourceAsFile(this,
                "nodejs/package.json"));
        final Dependency shrinkwrap = new Dependency(BaseTest.getResourceAsFile(this,
                "nodejs/npm-shrinkwrap.json"));
        engine.addDependency(packageJson);
        engine.addDependency(shrinkwrap);
        assertEquals(2, engine.getDependencies().length);
        analyzer.analyze(packageJson, engine);
        assertEquals(1, engine.getDependencies().length); //package-lock was removed without analysis
        assertEquals(shrinkwrap, engine.getDependencies()[0]);
        analyzer.analyze(shrinkwrap, engine);

        testLock();
    }

    /**
     * Test of inspect method, of class PythonDistributionAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testWithoutLock() throws AnalysisException, InvalidSettingException {
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED));
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED));
        final Dependency packageJson = new Dependency(BaseTest.getResourceAsFile(this,
                "nodejs/no_lock/package.json"));
        engine.addDependency(packageJson);
        analyzer.analyze(packageJson, engine);

        //final boolean isMac = !System.getProperty("os.name").toLowerCase().contains("mac");
        assertEquals(1, engine.getDependencies().length, "Expected 1 dependencies");
    }

    /**
     * Test of inspect method for package-lock v2
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testPackageLockV2() throws AnalysisException, InvalidSettingException {
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED));
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED));
        final Dependency packageJson = new Dependency(BaseTest.getResourceAsFile(this,
                "nodejs/test_lockv2/package.json"));
        final Dependency packageLockJson = new Dependency(BaseTest.getResourceAsFile(this,
                "nodejs/test_lockv2/package-lock.json"));
        engine.addDependency(packageJson);
        engine.addDependency(packageLockJson);
        analyzer.analyze(packageJson, engine);
        assertEquals(1, engine.getDependencies().length, "Expected 1 dependencies");
        analyzer.analyze(packageLockJson, engine);
        assertEquals(6, engine.getDependencies().length, "Expected 1 dependencies");
    }

    /**
     * Test of inspect method for package-lock v3
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testPackageLockV3() throws AnalysisException, InvalidSettingException {
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED));
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED));
        final Dependency packageJson = new Dependency(BaseTest.getResourceAsFile(this,
                "nodejs/test_lockv3/package.json"));
        final Dependency packageLockJson = new Dependency(BaseTest.getResourceAsFile(this,
                "nodejs/test_lockv3/package-lock.json"));
        engine.addDependency(packageJson);
        engine.addDependency(packageLockJson);
        analyzer.analyze(packageJson, engine);
        assertEquals(1, engine.getDependencies().length, "Expected 1 dependencies");
        analyzer.analyze(packageLockJson, engine);
        assertEquals(6, engine.getDependencies().length, "Expected 1 dependencies");
    }

    /**
     * Test of analysis of package with a local package as a dependency.
     *
     * This test crashes with an NPE if issue #1947 isn't resolved.
     *
     * @throws AnalysisException if there was a problem with the analysis
     */
    @Test
    void testLocalPackageDependency() throws AnalysisException, InvalidSettingException {
        assumeTrue(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED));
        final Dependency packageJson = new Dependency(BaseTest.getResourceAsFile(this,
                "nodejs/local_package/package.json"));
        final Dependency packageLockJson = new Dependency(BaseTest.getResourceAsFile(this,
                "nodejs/local_package/package-lock.json"));
        engine.addDependency(packageJson);
        engine.addDependency(packageLockJson);
        analyzer.analyze(packageJson, engine);
        assertEquals(1, engine.getDependencies().length, "Expected 1 dependencies");
        analyzer.analyze(packageLockJson, engine);
        assertEquals(2, engine.getDependencies().length, "Expected 2 dependencies");
    }
}
