/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ${package};

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test cases for ${analyzerName}
 */
class ${analyzerName}Test {

    Settings settings = null;

    ${analyzerName}Test() {
    }

    @BeforeAll
    static void setUpClass() {
    }

    @AfterAll
    static void tearDownClass() {
    }

    @BeforeEach
    void setUp() {
        settings = new Settings();
    }

    @AfterEach
    void tearDown() {
        settings.cleanup();
    }

    /**
     * Test of accept method, of class ${analyzerName}.
     */
    @Test
    void testAccept() {
        File pathname = new File("test.file");
        ${analyzerName} instance = new ${analyzerName}();
        boolean expResult = true;
        boolean result = instance.accept(pathname);
        assertEquals(expResult, result);
    }

    /**
     * Test of analyze method, of class ${analyzerName}.
     */
    @Test
    void testAnalyze() throws Exception {
        //The engine is generally null for most analyzer test cases but can be instantiated if needed.
        Engine engine = null;
        ${analyzerName} instance = new ${analyzerName}();
        instance.initialize(settings);
        instance.prepare(engine);

        File file = new File(${analyzerName}.class.getClassLoader().getResource("test.file").toURI().getPath());
        Dependency dependency = new Dependency(file);

        //TODO uncomment the following line and add assertions against the dependency.
        //instance.analyze(dependency, engine);
    }

    /**
     * Test of getName method, of class ${analyzerName}.
     */
    @Test
    void testGetName() {
        ${analyzerName} instance = new ${analyzerName}();
        String expResult = "${analyzerName}";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class ${analyzerName}.
     */
    @Test
    void testGetAnalysisPhase() {
        ${analyzerName} instance = new ${analyzerName}();
        AnalysisPhase expResult = AnalysisPhase.INFORMATION_COLLECTION;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of initialize method, of class ${analyzerName}.
     */
    @Test
    void testInitialize() throws Exception {
        ${analyzerName} instance = new ${analyzerName}();
        instance.initialize(settings);
    }

    /**
     * Test of close method, of class ${analyzerName}.
     */
    @Test
    void testClose() throws Exception {
        ${analyzerName} instance = new ${analyzerName}();
        instance.close();
    }

    /**
     * Test of supportsParallelProcessing method, of class ${analyzerName}.
     */
    @Test
    void testSupportsParallelProcessing() {
        ${analyzerName} instance = new ${analyzerName}();
        boolean expResult = true;
        boolean result = instance.supportsParallelProcessing();
        assertEquals(expResult, result);
    }

    /**
     * Test of isEnabled method, of class ${analyzerName}.
     */
    @Test
    void testIsEnabled() {
        ${analyzerName} instance = new ${analyzerName}();
        boolean expResult = true;
        boolean result = instance.isEnabled();
        assertEquals(expResult, result);
    }
}
