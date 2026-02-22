package org.owasp.dependencycheck.data.nexus;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MavenArtifactTest extends BaseTest {

    @Test
    void getPomUrl() {
        // Given
        final MavenArtifact mavenArtifact = new MavenArtifact("com.google.code.gson", "gson", "2.1",
                "https://artifactory.techno.ingenico.com/artifactory/jcenter-cache/com/google/code/gson/gson/2.1/gson-2.1.jar", MavenArtifact.derivePomUrl("gson", "2.1",
                        "https://artifactory.techno.ingenico.com/artifactory/jcenter-cache/com/google/code/gson/gson/2.1/gson-2.1.jar"));
        // When
        final String pomUrl = mavenArtifact.getPomUrl();
        // Then
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/jcenter-cache/com/google/code/gson/gson/2.1/gson-2.1.pom", pomUrl);

    }

    @Test
    void getPomUrlWithQualifier() {
        // Given
        final MavenArtifact mavenArtifact = new MavenArtifact("com.google.code.gson", "gson", "2.8.5",
                "https://artifactory.techno.ingenico.com/artifactory/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar", MavenArtifact.derivePomUrl("gson", "2.8.5",
                        "https://artifactory.techno.ingenico.com/artifactory/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5-sources.jar"));
        // When
        final String pomUrl = mavenArtifact.getPomUrl();
        // Then
        assertEquals("https://artifactory.techno.ingenico.com/artifactory/repo1-cache/com/google/code/gson/gson/2.8.5/gson-2.8.5.pom", pomUrl);

    }
}
