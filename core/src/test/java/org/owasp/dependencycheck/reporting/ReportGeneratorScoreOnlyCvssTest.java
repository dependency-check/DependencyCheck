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
 * Copyright (c) 2026 OWASP dependency-check contributors. All Rights Reserved.
 */
package org.owasp.dependencycheck.reporting;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2Data;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3Data;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4Data;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import us.springett.parsers.cpe.values.Part;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Generates every report format for a vulnerability whose CVSS data has a base
 * score and severity but no vector or metrics, as sources such as bundle-audit
 * provide, and checks the output is well-formed.
 */
class ReportGeneratorScoreOnlyCvssTest extends BaseTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    Path tempDir;

    @ParameterizedTest
    @ValueSource(strings = {"v2", "v3", "v4", "all"})
    void testScoreOnlyCvssRendersInEveryFormat(String versions) throws Exception {
        final Vulnerability vulnerability = new Vulnerability("GHSA-aaaa-bbbb-cccc");
        vulnerability.setSource(Vulnerability.Source.BUNDLEAUDIT);
        vulnerability.setDescription("A score-only vulnerability");
        if ("v2".equals(versions) || "all".equals(versions)) {
            final CvssV2Data data = new CvssV2Data(CvssV2Data.Version._2_0, null, null, null, null, null, null, 5.0, "MEDIUM",
                    null, null, null, null, null, null, null, null, null, null);
            vulnerability.setCvssV2(new CvssV2("test", CvssV2.Type.SECONDARY, data, "MEDIUM", null, null, null, null, null, null, null));
        }
        if ("v3".equals(versions) || "all".equals(versions)) {
            vulnerability.setCvssV3(new CvssV3("test", CvssV3.Type.SECONDARY,
                    new CvssV3Data(CvssV3Data.Version._3_1, null, 6.1, CvssV3Data.SeverityType.MEDIUM)));
        }
        if ("v4".equals(versions) || "all".equals(versions)) {
            vulnerability.setCvssV4(new CvssV4("test", CvssV4.Type.SECONDARY,
                    new CvssV4Data(CvssV4Data.Version._4_0, null, 8.7, CvssV4Data.SeverityType.HIGH)));
        }
        final VulnerableSoftware vs = new VulnerableSoftwareBuilder().part(Part.APPLICATION)
                .vendor("example").product("example_project").version("1.0.0").build();
        vulnerability.addVulnerableSoftware(vs);
        vulnerability.setMatchedVulnerableSoftware(vs);

        final File lockFile = tempDir.resolve("Gemfile.lock").toFile();
        final Dependency dependency = new Dependency(lockFile, true);
        dependency.setDisplayFileName("Gemfile.lock:example");
        dependency.setFileName("Gemfile.lock");
        dependency.setFilePath(lockFile.getPath());
        dependency.setSha1sum("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        dependency.setName("example");
        dependency.setVersion("1.0.0");
        dependency.addSoftwareIdentifier(new PurlIdentifier("gem", "example", "1.0.0", Confidence.HIGHEST));
        dependency.addVulnerability(vulnerability);

        final List<Dependency> dependencies = new ArrayList<>(List.of(dependency));
        final ReportGenerator generator = new ReportGenerator("Score-only CVSS", dependencies, new ArrayList<>(), null,
                getSettings(), null);

        for (ReportGenerator.Format format : ReportGenerator.Format.values()) {
            if (format == ReportGenerator.Format.ALL) {
                continue;
            }
            final Path outDir = Files.createDirectories(tempDir.resolve(format.name()));
            assertDoesNotThrow(() -> generator.write(outDir.toString(), format), format.name());
            final Path report = singleFile(outDir);
            final String content = Files.readString(report, StandardCharsets.UTF_8);
            switch (format) {
                case JSON:
                case SARIF:
                case GITLAB:
                    assertDoesNotThrow(() -> MAPPER.readTree(content), format + " is not valid JSON");
                    assertFalse(content.matches("(?s).*\\$!?(enc|rule|vuln|vulnerability)\\..*"),
                            format + " contains unrendered template references");
                    break;
                case XML:
                    validateXml(report);
                    break;
                default:
                    break;
            }
        }
    }

    private static Path singleFile(Path dir) throws Exception {
        try (Stream<Path> files = Files.walk(dir)) {
            final List<Path> found = files.filter(Files::isRegularFile).collect(Collectors.toList());
            assertEquals(1, found.size(), "expected one report in " + dir);
            return found.get(0);
        }
    }

    private static void validateXml(Path report) throws Exception {
        try (InputStream xsd = ReportGenerator.class.getClassLoader().getResourceAsStream("schema/dependency-check.4.1.xsd")) {
            SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
                    .newSchema(new StreamSource(xsd))
                    .newValidator()
                    .validate(new StreamSource(report.toFile()));
        }
    }
}
