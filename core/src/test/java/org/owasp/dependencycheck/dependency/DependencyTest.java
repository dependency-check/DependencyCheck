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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.dependency;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeBuilder;
import us.springett.parsers.cpe.values.Part;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Jeremy Long
 */
class DependencyTest extends BaseTest {

    /**
     * Test of getFileName method, of class Dependency.
     */
    @Test
    void testGetFileName() {
        Dependency instance = new Dependency();
        String expResult = "filename";
        instance.setFileName(expResult);
        String result = instance.getFileName();
        assertEquals(expResult, result);
    }

    /**
     * Test of setFileName method, of class Dependency.
     */
    @Test
    void testSetFileName() {
        String fileName = "file.tar";
        Dependency instance = new Dependency();
        instance.setFileName(fileName);
        assertEquals(fileName, instance.getFileName());
    }

    /**
     * Test of setActualFilePath method, of class Dependency.
     */
    @Test
    void testSetActualFilePath() {
        String expectedPath = "file.tar";
        String actualPath = "file.tar";
        Dependency instance = new Dependency();
        instance.setSha1sum("non-null value");
        instance.setActualFilePath(actualPath);
        assertEquals(expectedPath, instance.getActualFilePath());
    }

    /**
     * Test of getActualFilePath method, of class Dependency.
     */
    @Test
    void testGetActualFilePath() {
        Dependency instance = new Dependency();
        String expResult = "file.tar";
        instance.setSha1sum("non-null value");
        instance.setActualFilePath(expResult);
        String result = instance.getActualFilePath();
        assertEquals(expResult, result);
    }

    /**
     * Test of setFilePath method, of class Dependency.
     */
    @Test
    void testSetFilePath() {
        String filePath = "file.tar";
        Dependency instance = new Dependency();
        instance.setFilePath(filePath);
        assertEquals(filePath, instance.getFilePath());
    }

    /**
     * Test of getFilePath method, of class Dependency.
     */
    @Test
    void testGetFilePath() {
        Dependency instance = new Dependency();
        String expResult = "file.tar";
        instance.setFilePath(expResult);
        String result = instance.getFilePath();
        assertEquals(expResult, result);
    }

    /**
     * Test of getMd5sum method, of class Dependency.
     */
    @Test
    void testGetMd5sum() {
        File file = BaseTest.getResourceAsFile(this, "maven-lib/struts2-core-2.1.2.jar");

        Dependency instance = new Dependency(file);
        //assertEquals("89CE9E36AA9A9E03F1450936D2F4F8DD0F961F8B", result.getSha1sum());
        //String expResult = "C30B57142E1CCBC1EFD5CD15F307358F";
        String expResult = "c30b57142e1ccbc1efd5cd15f307358f";
        String result = instance.getMd5sum();
        assertEquals(expResult, result);
    }

    /**
     * Test of setMd5sum method, of class Dependency.
     */
    @Test
    void testSetMd5sum() {
        String md5sum = "test";
        Dependency instance = new Dependency();
        instance.setMd5sum(md5sum);
        assertEquals(md5sum, instance.getMd5sum());
    }

    /**
     * Test of getSha1sum method, of class Dependency.
     */
    @Test
    void testGetSha1sum() {
        File file = BaseTest.getResourceAsFile(this, "maven-lib/struts2-core-2.1.2.jar");
        Dependency instance = new Dependency(file);
        //String expResult = "89CE9E36AA9A9E03F1450936D2F4F8DD0F961F8B";
        String expResult = "89ce9e36aa9a9e03f1450936d2f4f8dd0f961f8b";
        String result = instance.getSha1sum();
        assertEquals(expResult, result);
    }

    /**
     * Test of getSha256sum method, of class Dependency.
     */
    @Test
    void testGetSha256sum() {
        File file = BaseTest.getResourceAsFile(this, "maven-lib/struts2-core-2.1.2.jar");
        Dependency instance = new Dependency(file);
        String expResult = "5c1847a10800027254fcd0073385cceb46b1dacee061f3cd465e314bec592e81";
        String result = instance.getSha256sum();
        assertEquals(expResult, result);
    }

    /**
     * Test of setSha1sum method, of class Dependency.
     */
    @Test
    void testSetSha1sum() {
        String sha1sum = "test";
        Dependency instance = new Dependency();
        instance.setSha1sum(sha1sum);
        assertEquals(sha1sum, instance.getSha1sum());
    }

    /**
     * Test of setSha256sum method, of class Dependency.
     */
    @Test
    void testSetSha256sum() {
        String sha256sum = "test";
        Dependency instance = new Dependency();
        instance.setSha256sum(sha256sum);
        assertEquals(sha256sum, instance.getSha256sum());
    }

    /**
     * Test of getSoftwareIdentifiers method, of class Dependency.
     */
    @Test
    void testGetSoftwareIdentifiers() {
        Dependency instance = new Dependency();
        Set<Identifier> result = instance.getSoftwareIdentifiers();

        assertNotNull(result);
    }

    /**
     * Test of addSoftwareIdentifiers method, of class Dependency.
     */
    @Test
    void testAddSoftwareIdentifiers() {
        Set<Identifier> identifiers = new HashSet<>();
        Dependency instance = new Dependency();
        instance.addSoftwareIdentifiers(identifiers);
        assertNotNull(instance.getSoftwareIdentifiers());
    }

    /**
     * Test of addVulnerableSoftwareIdentifier method, of class Dependency.
     */
    @Test
    void testAddVulnerableSoftwareIdentifier() throws Exception {
        CpeBuilder builder = new CpeBuilder();
        Cpe cpe = builder.part(Part.APPLICATION).vendor("apache").product("struts").version("2.1.2").build();
        CpeIdentifier id = new CpeIdentifier(cpe, Confidence.HIGHEST);

        cpe = builder.part(Part.APPLICATION).vendor("apache").product("struts").version("2.1.2").build();
        CpeIdentifier expResult = new CpeIdentifier(cpe, Confidence.HIGHEST);

        Dependency instance = new Dependency();
        instance.addVulnerableSoftwareIdentifier(id);
        assertEquals(1, instance.getVulnerableSoftwareIdentifiers().size());
        assertTrue(instance.getVulnerableSoftwareIdentifiers().contains(expResult), "Identifier doesn't contain expected result.");
    }

    /**
     * Test of getEvidence method, of class Dependency.
     */
    @Test
    void testGetEvidence() {
        Dependency instance = new Dependency();
        Set<Evidence> result = instance.getEvidence(EvidenceType.VENDOR);
        assertNotNull(result);
        result = instance.getEvidence(EvidenceType.PRODUCT);
        assertNotNull(result);
        result = instance.getEvidence(EvidenceType.VERSION);
        assertNotNull(result);
    }

    /**
     * Test of addAsEvidence method, of class Dependency.
     */
    @Test
    void testAddAsEvidence() {
        Dependency instance = new Dependency();
        MavenArtifact mavenArtifact = new MavenArtifact("group", "artifact", "version", "url");
        instance.addAsEvidence("pom", mavenArtifact, Confidence.HIGH);
        assertTrue(instance.contains(EvidenceType.VENDOR, Confidence.HIGH));
        assertEquals(4, instance.size());
        assertFalse(instance.getSoftwareIdentifiers().isEmpty());
    }

    /**
     * Test of addAsEvidence method, of class Dependency.
     */
    @Test
    void testAddAsEvidenceWithEmptyArtifact() {
        Dependency instance = new Dependency();
        MavenArtifact mavenArtifact = new MavenArtifact(null, null, null, null);
        instance.addAsEvidence("pom", mavenArtifact, Confidence.HIGH);
        assertFalse(instance.getEvidence(EvidenceType.VENDOR).stream().anyMatch(e -> e.getConfidence() == Confidence.HIGH));
        assertEquals(0, instance.size());
        assertTrue(instance.getSoftwareIdentifiers().isEmpty());
    }

    /**
     * Test of addAsEvidence method, of class Dependency.
     */
    @Test
    void testAddAsEvidenceWithExisting() {
        Dependency instance = new Dependency();
        MavenArtifact mavenArtifact = new MavenArtifact("group", "artifact", "version", null);
        instance.addAsEvidence("pom", mavenArtifact, Confidence.HIGH);
        assertTrue(instance.getEvidence(EvidenceType.VENDOR).stream().anyMatch(e -> e.getConfidence() == Confidence.HIGH));
        assertEquals(4, instance.size());
        assertFalse(instance.getSoftwareIdentifiers().isEmpty());

        instance.getSoftwareIdentifiers().forEach((i) -> assertNull(i.getUrl()));

        mavenArtifact = new MavenArtifact("group", "artifact", "version", "url");
        instance.addAsEvidence("pom", mavenArtifact, Confidence.HIGH);
        assertTrue(instance.getEvidence(EvidenceType.VENDOR).stream().anyMatch(e -> e.getConfidence() == Confidence.HIGH));
        assertEquals(4, instance.size());
        assertFalse(instance.getSoftwareIdentifiers().isEmpty());

        instance.getSoftwareIdentifiers().forEach((i) -> assertNotNull(i.getUrl()));
    }
}
