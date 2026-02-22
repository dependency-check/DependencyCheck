package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;

import java.io.File;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for CocoaPodsAnalyzer, CarthageAnalyzer and SwiftPackageManagerAnalyzer.
 *
 * @author Bianca Jiang
 * @author Jorge Mendes
 * @author Alin Radut
 */
class SwiftAnalyzersTest extends BaseTest {

    /**
     * The analyzer to test.
     */
    private CocoaPodsAnalyzer podsAnalyzer;
    private CarthageAnalyzer carthageAnalyzer;
    private SwiftPackageManagerAnalyzer spmAnalyzer;
    private SwiftPackageResolvedAnalyzer sprAnalyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        podsAnalyzer = new CocoaPodsAnalyzer();
        podsAnalyzer.initialize(getSettings());
        podsAnalyzer.setFilesMatched(true);
        podsAnalyzer.prepare(null);

        carthageAnalyzer = new CarthageAnalyzer();
        carthageAnalyzer.initialize(getSettings());
        carthageAnalyzer.setFilesMatched(true);
        carthageAnalyzer.prepare(null);

        spmAnalyzer = new SwiftPackageManagerAnalyzer();
        spmAnalyzer.initialize(getSettings());
        spmAnalyzer.setFilesMatched(true);
        spmAnalyzer.prepare(null);

        sprAnalyzer = new SwiftPackageResolvedAnalyzer();
        sprAnalyzer.initialize(getSettings());
        sprAnalyzer.setFilesMatched(true);
        sprAnalyzer.prepare(null);
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @AfterEach
    @Override
    public void tearDown() throws Exception {
        podsAnalyzer.close();
        podsAnalyzer = null;

        spmAnalyzer.close();
        spmAnalyzer = null;

        super.tearDown();
    }

    /**
     * Test of getName method, of class CocoaPodsAnalyzer.
     */
    @Test
    void testPodsGetName() {
        assertThat(podsAnalyzer.getName(), is("CocoaPods Package Analyzer"));
    }

    /**
     * Test of getName method, of class CarthageAnalyzer.
     */
    @Test
    void testCarthageGetName() {
        assertThat(carthageAnalyzer.getName(), is("Carthage Package Analyzer"));
    }

    /**
     * Test of getName method, of class SwiftPackageManagerAnalyzer.
     */
    @Test
    void testSPMGetName() {
        assertThat(spmAnalyzer.getName(), is("SWIFT Package Manager Analyzer"));
    }

    /**
     * Test of supportsFiles method, of class CocoaPodsAnalyzer.
     */
    @Test
    void testPodsSupportsFiles() {
        assertThat(podsAnalyzer.accept(new File("test.podspec")), is(true));
        assertThat(podsAnalyzer.accept(new File("Podfile.lock")), is(true));
    }

    /**
     * Test of supportsFiles method, of class CocoaPodsAnalyzer.
     */
    @Test
    void testCarthageSupportsFiles() {
        assertThat(carthageAnalyzer.accept(new File("Cartfile.resolved")), is(true));
    }

    /**
     * Test of supportsFiles method, of class SwiftPackageManagerAnalyzer.
     */
    @Test
    void testSPMSupportsFiles() {
        assertThat(spmAnalyzer.accept(new File("Package.swift")), is(true));
        assertThat(sprAnalyzer.accept(new File("Package.resolved")), is(true));
    }

    /**
     * Test of analyze method, of class CocoaPodsAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testCocoaPodsPodfileAnalyzer() throws AnalysisException {
        final Engine engine = new Engine(getSettings());
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "swift/cocoapods/Podfile.lock"));
        podsAnalyzer.analyze(result, engine);

        assertThat(engine.getDependencies().length, equalTo(9));
        assertThat(engine.getDependencies()[0].getName(), equalTo("Bolts"));
        assertThat(engine.getDependencies()[0].getVersion(), equalTo("1.9.0"));
        assertThat(engine.getDependencies()[1].getName(), equalTo("Bolts/AppLinks"));
        assertThat(engine.getDependencies()[1].getVersion(), equalTo("1.9.0"));
        assertThat(engine.getDependencies()[2].getName(), equalTo("Bolts/Tasks"));
        assertThat(engine.getDependencies()[2].getVersion(), equalTo("1.9.0"));
        assertThat(engine.getDependencies()[3].getName(), equalTo("FBSDKCoreKit"));
        assertThat(engine.getDependencies()[3].getVersion(), equalTo("4.33.0"));
        assertThat(engine.getDependencies()[4].getName(), equalTo("FBSDKLoginKit"));
        assertThat(engine.getDependencies()[4].getVersion(), equalTo("4.33.0"));
        assertThat(engine.getDependencies()[5].getName(), equalTo("FirebaseCore"));
        assertThat(engine.getDependencies()[5].getVersion(), equalTo("5.0.1"));
        assertThat(engine.getDependencies()[6].getName(), equalTo("GoogleToolboxForMac/Defines"));
        assertThat(engine.getDependencies()[6].getVersion(), equalTo("2.1.4"));
        assertThat(engine.getDependencies()[7].getName(), equalTo("GoogleToolboxForMac/NSData+zlib"));
        assertThat(engine.getDependencies()[7].getVersion(), equalTo("2.1.4"));
        assertThat(engine.getDependencies()[8].getName(), equalTo("OCMock"));
        assertThat(engine.getDependencies()[8].getVersion(), equalTo("3.4.1"));
    }

    @Test
    void testCocoaPodsPodspecAnalyzer() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "swift/cocoapods/EasyPeasy.podspec"));
        podsAnalyzer.analyze(result, null);
        final String vendorString = result.getEvidence(EvidenceType.VENDOR).toString();

        assertThat(vendorString, containsString("Carlos Vidal"));
        assertThat(vendorString, containsString("https://github.com/nakiostudio/EasyPeasy"));
        assertThat(result.getEvidence(EvidenceType.PRODUCT).toString(), containsString("EasyPeasy"));
        assertThat(result.getEvidence(EvidenceType.VERSION).toString(), containsString("0.2.3"));
        assertThat(result.getName(), equalTo("EasyPeasy"));
        assertThat(result.getVersion(), equalTo("0.2.3"));
        assertThat(result.getDisplayFileName(), equalTo("EasyPeasy:0.2.3"));
        assertThat(result.getLicense(), containsString("MIT"));
        assertThat(result.getEcosystem(), equalTo(CocoaPodsAnalyzer.DEPENDENCY_ECOSYSTEM));
    }

    /**
     * Test of analyze method, of class CarthageAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testCarthageCartfileResolvedAnalyzer() throws AnalysisException {
        final Engine engine = new Engine(getSettings());
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "swift/carthage/Cartfile.resolved"));
        carthageAnalyzer.analyze(result, engine);

        assertThat(engine.getDependencies().length, equalTo(9));
        assertThat(engine.getDependencies()[0].getName(), equalTo("GoogleMaps"));
        assertThat(engine.getDependencies()[0].getVersion(), equalTo("7.2.0"));
        assertThat(engine.getDependencies()[1].getName(), equalTo("olm"));
        assertThat(engine.getDependencies()[1].getVersion(), equalTo("3.2.16"));
        assertThat(engine.getDependencies()[2].getName(), equalTo("CocoaLumberjack"));
        assertThat(engine.getDependencies()[2].getVersion(), equalTo("3.8.5"));
        assertThat(engine.getDependencies()[3].getName(), equalTo("libidn-framework"));
        assertThat(engine.getDependencies()[3].getVersion(), equalTo("1.35.1"));
        assertThat(engine.getDependencies()[4].getName(), equalTo("SQLite.swift"));
        assertThat(engine.getDependencies()[4].getVersion(), equalTo("0.12.2"));
        assertThat(engine.getDependencies()[5].getName(), equalTo("KissXML"));
        assertThat(engine.getDependencies()[5].getVersion(), equalTo("5.3.3"));
        assertThat(engine.getDependencies()[6].getName(), equalTo("XMPPFramework"));
        assertThat(engine.getDependencies()[6].getVersion(), equalTo("4.1.0"));
        assertThat(engine.getDependencies()[7].getName(), equalTo("Alamofire"));
        assertThat(engine.getDependencies()[7].getVersion(), equalTo("4.8.2"));
        assertThat(engine.getDependencies()[8].getName(), equalTo("DateTools"));
        assertThat(engine.getDependencies()[8].getVersion(), equalTo("0.0.0"));
    }

    /**
     * Test of analyze method, of class SwiftPackageManagerAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    void testSPMAnalyzer() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "swift/Gloss/Package.swift"));
        spmAnalyzer.analyze(result, null);

        assertThat(result.getEvidence(EvidenceType.PRODUCT).toString(), containsString("Gloss"));
        assertThat(result.getName(), equalTo("Gloss"));
        //TODO: when version processing is added, update the expected name.
        assertThat(result.getDisplayFileName(), equalTo("Gloss"));
        assertThat(result.getEcosystem(), equalTo(SwiftPackageManagerAnalyzer.DEPENDENCY_ECOSYSTEM));
    }

    @Test
    void testSPMResolvedAnalyzerV1() throws AnalysisException {
        final Engine engine = new Engine(getSettings());
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "swift/spm/Package.resolved"));
        sprAnalyzer.analyze(result, engine);

        assertThat(engine.getDependencies().length, equalTo(3));
        assertThat(engine.getDependencies()[0].getName(), equalTo("Alamofire"));
        assertThat(engine.getDependencies()[0].getVersion(), equalTo("5.4.3"));
        assertThat(engine.getDependencies()[1].getName(), equalTo("AlamofireImage"));
        assertThat(engine.getDependencies()[1].getVersion(), equalTo("4.2.0"));
        assertThat(engine.getDependencies()[2].getName(), equalTo("Facebook"));
        assertThat(engine.getDependencies()[2].getVersion(), equalTo("9.3.0"));
    }

    @Test
    void testSPMResolvedAnalyzerV2() throws AnalysisException {
        final Engine engine = new Engine(getSettings());
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "swift/spmV2/Package.resolved"));
        sprAnalyzer.analyze(result, engine);

        assertThat(engine.getDependencies().length, equalTo(3));
        assertThat(engine.getDependencies()[0].getName(), equalTo("alamofire"));
        assertThat(engine.getDependencies()[0].getVersion(), equalTo("5.4.3"));
        assertThat(engine.getDependencies()[1].getName(), equalTo("alamofireimage"));
        assertThat(engine.getDependencies()[1].getVersion(), equalTo("4.2.0"));
        assertThat(engine.getDependencies()[2].getName(), equalTo("facebook"));
        assertThat(engine.getDependencies()[2].getVersion(), equalTo("9.3.0"));
    }

    @Test
    void testSPMResolvedAnalyzerV3() throws AnalysisException {
        final Engine engine = new Engine(getSettings());
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "swift/spmV3/Package.resolved"));
        sprAnalyzer.analyze(result, engine);

        assertThat(engine.getDependencies().length, equalTo(3));
        assertThat(engine.getDependencies()[0].getName(), equalTo("alamofire"));
        assertThat(engine.getDependencies()[0].getVersion(), equalTo("5.4.3"));
        assertThat(engine.getDependencies()[1].getName(), equalTo("alamofireimage"));
        assertThat(engine.getDependencies()[1].getVersion(), equalTo("4.2.0"));
        assertThat(engine.getDependencies()[2].getName(), equalTo("facebook-ios-sdk"));
        assertThat(engine.getDependencies()[2].getVersion(), equalTo("9.3.0"));
    }

    @Test
    void testIsEnabledIsTrueByDefault() {
        assertTrue(spmAnalyzer.isEnabled());
        assertTrue(sprAnalyzer.isEnabled());
    }
}
