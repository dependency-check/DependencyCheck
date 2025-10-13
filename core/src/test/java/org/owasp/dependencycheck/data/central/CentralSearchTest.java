package org.owasp.dependencycheck.data.central;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Created by colezlaw on 10/13/14.
 */
class CentralSearchTest extends BaseTest {

    private CentralSearch searcher;

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
        searcher = new CentralSearch(getSettings());
    }

    @Test
    void testNullSha1() {
        assertThrows(IllegalArgumentException.class, () ->
            searcher.searchSha1(null));
    }

    @Test
    void testMalformedSha1() {
        assertThrows(IllegalArgumentException.class, () ->
            searcher.searchSha1("invalid"));
    }

    // This test does generate network traffic and communicates with a host
    // you may not be able to reach. Remove the @Ignore annotation if you want to
    // test it anyway
    @Test
    void testValidSha1() throws Exception {
        try {
            List<MavenArtifact> ma = searcher.searchSha1("9977a8d04e75609cf01badc4eb6a9c7198c4c5ea");
            assertEquals("org.apache.maven.plugins", ma.get(0).getGroupId(), "Incorrect group");
            assertEquals("maven-compiler-plugin", ma.get(0).getArtifactId(), "Incorrect artifact");
            assertEquals("3.1", ma.get(0).getVersion(), "Incorrect version");
        } catch (SocketTimeoutException ex) {
            // skip test if Maven Central times out
            assumeTrue(false, "Skipping test due to SocketTimeoutException: " + ex.getMessage());
        } catch (IOException ex) {
            // abort if we hit a failure state on the CI
            assumeFalse(StringUtils.contains(ex.getMessage(), "Could not connect to MavenCentral"));
            assumeFalse(ex.getMessage().matches("^https://.+ - Server status: \\d{3} - Server reason: .+$"));

            // otherwise fail the test
            throw ex;
        }
    }

    // This test does generate network traffic and communicates with a host
    // you may not be able to reach. Remove the @Ignore annotation if you want to
    // test it anyway
    @Test
    void testMissingSha1() throws Exception {
        try {
            searcher.searchSha1("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        } catch (SocketTimeoutException ex) {
            // skip test if Maven Central times out
            assumeTrue(false, "Skipping test due to SocketTimeoutException: " + ex.getMessage());
        } catch (IOException ex) {
            // abort if we hit a failure state on the CI
            assumeFalse(StringUtils.contains(ex.getMessage(), "Could not connect to MavenCentral"));
            assumeFalse(ex.getMessage().matches("^https://.+ - Server status: \\d{3} - Server reason: .+$"));

            // otherwise assert that the exception is a FileNotFoundException
            assertInstanceOf(FileNotFoundException.class, ex);
            assertEquals("Artifact not found in Central", ex.getMessage());
        }
    }

    // This test should give us multiple results back from Central
    @Test
    void testMultipleReturns() throws Exception {
        try {
            List<MavenArtifact> ma = searcher.searchSha1("94A9CE681A42D0352B3AD22659F67835E560D107");
            assertTrue(ma.size() > 1);
        } catch (SocketTimeoutException ex) {
            // skip test if Maven Central times out
            assumeTrue(false, "Skipping test due to SocketTimeoutException: " + ex.getMessage());
        } catch (IOException ex) {
            // abort if we hit a failure state on the CI
            assumeFalse(StringUtils.contains(ex.getMessage(), "Could not connect to MavenCentral"));
            assumeFalse(ex.getMessage().matches("^https://.+ - Server status: \\d{3} - Server reason: .+$"));

            // otherwise fail the test
            throw ex;
        }
    }
}
