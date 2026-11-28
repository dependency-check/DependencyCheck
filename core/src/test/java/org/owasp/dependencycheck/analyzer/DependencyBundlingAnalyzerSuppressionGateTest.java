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
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import com.github.packageurl.MalformedPackageURLException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the suppression state gate of the {@link DependencyBundlingAnalyzer}. Suppression rules are
 * matched per file and run before bundling, so two dependencies that would otherwise be bundled can
 * legitimately carry different suppression state - see issue #5031.
 */
class DependencyBundlingAnalyzerSuppressionGateTest extends BaseTest {

    private static final String SHA1 = "1234567890abcdef1234567890abcdef12345678";

    private DependencyBundlingAnalyzer analyzer;

    @BeforeEach
    void setUpAnalyzer() {
        analyzer = new DependencyBundlingAnalyzer();
        analyzer.initialize(new Settings());
    }

    /**
     * Two copies of the same file, only one of them suppressed. The gate has to keep both.
     */
    @Test
    void testHashesMatchWithDifferentSuppressedVulnerabilitiesIsNotBundled() {
        final Dependency left = new Dependency(new File("/path/a.jar"), true);
        final Dependency right = new Dependency(new File("/path/b/c.jar"), true);
        left.setSha1sum(SHA1);
        right.setSha1sum(SHA1);
        right.addSuppressedVulnerability(new Vulnerability("CVE-2016-1000027"));

        final Set<Dependency> toRemove = new HashSet<>();
        assertFalse(analyzer.evaluateDependencies(left, right, toRemove));
        assertTrue(toRemove.isEmpty(), "dependencies with different suppression state must not be bundled");
        assertTrue(left.getRelatedDependencies().isEmpty());
        assertEquals(0, left.getSuppressedVulnerabilities().size(),
                "only the related copy carries the suppressed finding");
        assertEquals(1, right.getSuppressedVulnerabilities().size());
    }

    /**
     * Same as above but the suppression only covers a vulnerable software identifier.
     */
    @Test
    void testHashesMatchWithDifferentSuppressedIdentifiersIsNotBundled() throws MalformedPackageURLException {
        final Dependency left = new Dependency(new File("/path/a.jar"), true);
        final Dependency right = new Dependency(new File("/path/b/c.jar"), true);
        left.setSha1sum(SHA1);
        right.setSha1sum(SHA1);
        right.addSuppressedIdentifier(new PurlIdentifier("maven", "org.springframework", "spring-web",
                "5.3.23", Confidence.HIGHEST));

        final Set<Dependency> toRemove = new HashSet<>();
        assertFalse(analyzer.evaluateDependencies(left, right, toRemove));
        assertTrue(toRemove.isEmpty(), "dependencies with different suppression state must not be bundled");
        assertEquals(1, right.getSuppressedIdentifiers().size());
    }

    /**
     * Regression guard: two unsuppressed copies still bundle as before.
     */
    @Test
    void testHashesMatchWithoutSuppressionIsStillBundled() {
        final Dependency left = new Dependency(new File("/path/a.jar"), true);
        final Dependency right = new Dependency(new File("/path/b/c.jar"), true);
        left.setSha1sum(SHA1);
        right.setSha1sum(SHA1);

        final Set<Dependency> toRemove = new HashSet<>();
        assertFalse(analyzer.evaluateDependencies(left, right, toRemove));
        assertEquals(1, toRemove.size());
        assertTrue(toRemove.contains(right));
        assertEquals(1, left.getRelatedDependencies().size());
    }

    /**
     * Regression guard: identical suppression state on both copies still bundles.
     */
    @Test
    void testHashesMatchWithIdenticalSuppressionIsStillBundled() {
        final Dependency left = new Dependency(new File("/path/a.jar"), true);
        final Dependency right = new Dependency(new File("/path/b/c.jar"), true);
        left.setSha1sum(SHA1);
        right.setSha1sum(SHA1);
        left.addSuppressedVulnerability(new Vulnerability("CVE-2016-1000027"));
        right.addSuppressedVulnerability(new Vulnerability("CVE-2016-1000027"));

        final Set<Dependency> toRemove = new HashSet<>();
        assertFalse(analyzer.evaluateDependencies(left, right, toRemove));
        assertEquals(1, toRemove.size());
    }

    /**
     * The scenario of issue #5031: the active findings match, only the suppressed one differs. Before
     * the gate this pair was merged at all because the suppression emptied the active collection of the
     * related dependency.
     */
    @Test
    void testCpeMatchWithDifferentSuppressedVulnerabilitiesIsNotBundled() throws MalformedPackageURLException {
        final Dependency core = cpeDependency();
        final Dependency web = cpeDependency();
        core.setSha1sum("aaa");
        web.setSha1sum("bbb");
        final Vulnerability active = new Vulnerability("CVE-2022-22965");
        core.addVulnerability(active);
        web.addVulnerability(active);
        web.addSuppressedVulnerability(new Vulnerability("CVE-2016-1000027"));

        final Set<Dependency> toRemove = new HashSet<>();
        assertFalse(analyzer.evaluateDependencies(core, web, toRemove));
        assertTrue(toRemove.isEmpty(), "#5031: a suppressed finding must not be bundled away");
        assertEquals(1, web.getSuppressedVulnerabilities().size());
        assertEquals(1, web.getVulnerabilities().size());
    }

    /**
     * Control for the case above: with identical suppression state the CPE branch still bundles.
     */
    @Test
    void testCpeMatchWithIdenticalSuppressionIsStillBundled() throws MalformedPackageURLException {
        final Dependency core = cpeDependency();
        final Dependency web = cpeDependency();
        core.setSha1sum("aaa");
        web.setSha1sum("bbb");
        final Vulnerability active = new Vulnerability("CVE-2022-22965");
        core.addVulnerability(active);
        web.addVulnerability(active);
        core.addSuppressedVulnerability(new Vulnerability("CVE-2016-1000027"));
        web.addSuppressedVulnerability(new Vulnerability("CVE-2016-1000027"));

        final Set<Dependency> toRemove = new HashSet<>();
        assertFalse(analyzer.evaluateDependencies(core, web, toRemove));
        assertEquals(1, toRemove.size());
    }

    /**
     * Shaded jar branch: the pom.xml is suppressed, the jar is not. Both are kept.
     */
    @Test
    void testShadedJarWithDifferentSuppressedVulnerabilitiesIsNotBundled() throws MalformedPackageURLException {
        final Dependency jar = shadedJar();
        final Dependency pom = shadedPom();
        pom.addSuppressedVulnerability(new Vulnerability("CVE-2020-0001"));

        final Set<Dependency> toRemove = new HashSet<>();
        assertFalse(analyzer.evaluateDependencies(jar, pom, toRemove));
        assertTrue(toRemove.isEmpty(), "the shaded pom must keep its own suppression state");

        final Dependency controlJar = shadedJar();
        final Dependency controlPom = shadedPom();
        final Set<Dependency> controlRemove = new HashSet<>();
        assertFalse(analyzer.evaluateDependencies(controlJar, controlPom, controlRemove));
        assertEquals(1, controlRemove.size(), "without suppression the shaded jar still bundles");
    }

    /**
     * WebJar branch: the javascript file is suppressed, the jar is not. Both are kept.
     */
    @Test
    void testWebJarWithDifferentSuppressedVulnerabilitiesIsNotBundled() throws MalformedPackageURLException {
        final Dependency jar = webJar();
        final Dependency js = webJarScript();
        js.addSuppressedVulnerability(new Vulnerability("CVE-2019-11358"));

        final Set<Dependency> toRemove = new HashSet<>();
        assertFalse(analyzer.evaluateDependencies(jar, js, toRemove));
        assertTrue(toRemove.isEmpty(), "the javascript file must keep its own suppression state");

        final Dependency controlJar = webJar();
        final Dependency controlJs = webJarScript();
        final Set<Dependency> controlRemove = new HashSet<>();
        assertFalse(analyzer.evaluateDependencies(controlJar, controlJs, controlRemove));
        assertEquals(1, controlRemove.size(), "without suppression the webjar still bundles");
    }

    private static Dependency cpeDependency() throws MalformedPackageURLException {
        final Dependency dependency = new Dependency(new File("/repo/spring-core-5.3.23.jar"), true);
        dependency.addVulnerableSoftwareIdentifier(new PurlIdentifier("maven", "org.springframework",
                "spring-framework", "5.3.23", Confidence.HIGH));
        return dependency;
    }

    private static Dependency shadedJar() throws MalformedPackageURLException {
        final Dependency dependency = new Dependency(new File("/path/app.jar"), true);
        dependency.addSoftwareIdentifier(new PurlIdentifier("maven", "test", "test", "1.0", Confidence.HIGHEST));
        return dependency;
    }

    private static Dependency shadedPom() throws MalformedPackageURLException {
        final Dependency dependency = new Dependency(new File("/path/pom.xml"), true);
        dependency.addSoftwareIdentifier(new PurlIdentifier("maven", "test", "test", "1.0", Confidence.HIGHEST));
        return dependency;
    }

    private static Dependency webJar() throws MalformedPackageURLException {
        final Dependency dependency = new Dependency(new File("/path/jquery.jar"), true);
        dependency.addSoftwareIdentifier(new PurlIdentifier("maven", "org.webjars", "jquery", "1.0",
                Confidence.HIGHEST));
        return dependency;
    }

    private static Dependency webJarScript() throws MalformedPackageURLException {
        final Dependency dependency = new Dependency(new File("/path/jquery.js"), true);
        dependency.setFileName("jquery.jar: jquery.js");
        dependency.addSoftwareIdentifier(new PurlIdentifier("javascript", "jquery", "1.0", Confidence.HIGHEST));
        return dependency;
    }
}