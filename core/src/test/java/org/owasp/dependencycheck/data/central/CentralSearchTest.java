package org.owasp.dependencycheck.data.central;

import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;

import java.io.IOException;
import java.util.List;
import org.apache.commons.lang3.StringUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Assume;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Created by colezlaw on 10/13/14.
 */
public class CentralSearchTest extends BaseTest {

    private CentralSearch searcher;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        searcher = new CentralSearch(getSettings());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNullSha1() throws Exception {
        searcher.searchSha1(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMalformedSha1() throws Exception {
        searcher.searchSha1("invalid");
    }

    // This test does generate network traffic and communicates with a host
    // you may not be able to reach. Remove the @Ignore annotation if you want to
    // test it anyway
    @Test
    public void testValidSha1() throws Exception {
        try {
            List<MavenArtifact> ma = searcher.searchSha1("9977a8d04e75609cf01badc4eb6a9c7198c4c5ea");
            assertEquals("Incorrect group", "org.apache.maven.plugins", ma.get(0).getGroupId());
            assertEquals("Incorrect artifact", "maven-compiler-plugin", ma.get(0).getArtifactId());
            assertEquals("Incorrect version", "3.1", ma.get(0).getVersion());
        } catch (IOException ex) {
            //we hit a failure state on the CI
            Assume.assumeFalse(StringUtils.contains(ex.getMessage(), "Could not connect to MavenCentral"));
            throw ex;
        }
    }

    // This test does generate network traffic and communicates with a host
    // you may not be able to reach. Remove the @Ignore annotation if you want to
    // test it anyway
    @Test(expected = IOException.class)
    public void testMissingSha1() throws Exception {
        try {
            List<MavenArtifact> results = searcher.searchSha1("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            assertTrue(results.isEmpty());
        } catch (IOException ex) {
            //we hit a failure state on the CI
            Assume.assumeFalse(StringUtils.contains(ex.getMessage(), "Could not connect to MavenCentral"));
            throw ex;
        }
    }

    // This test should give us multiple results back from Central
    @Test
    public void testMultipleReturns() throws Exception {
        try {

            List<MavenArtifact> ma = searcher.searchSha1("94a9ce681a42d0352b3ad22659f67835e560d107");
            assertTrue(ma.size() > 1);
        } catch (IOException ex) {
            //we hit a failure state on the CI
            Assume.assumeFalse(StringUtils.contains(ex.getMessage(), "Could not connect to MavenCentral"));
            throw ex;
        }
    }
}
