package org.owasp.dependencycheck.data.nvd.ecosystem;

import io.github.jeremylong.openvulnerability.client.nvd.CveItem;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import io.github.jeremylong.openvulnerability.client.nvd.LangString;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class DescriptionEcosystemMapperTest {

    private static final String POSTFIX = ".ecosystem.txt";

    protected static final File directory = new File("./src/test/resources/ecosystem");

    protected static Map<String, File> getEcosystemFiles() throws IOException {
        if (!directory.exists()) {
            throw new RuntimeException(directory.getCanonicalPath());
        }

        File[] listFiles = directory.listFiles((d, name) -> name.endsWith(POSTFIX));

        Map<String, File> map = new HashMap<>();
        for (File file : listFiles) {
            String name = file.getName();
            map.put(name.substring(0, name.length() - POSTFIX.length()), file);
        }
        return map;
    }

    @Test
    void testDescriptionEcosystemMapper() throws IOException {
        DescriptionEcosystemMapper mapper = new DescriptionEcosystemMapper();
        Map<String, File> ecosystemFiles = getEcosystemFiles();
        for (Entry<String, File> entry : ecosystemFiles.entrySet()) {
            try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(entry.getValue()), StandardCharsets.UTF_8))) {
                String description;
                while ((description = bufferedReader.readLine()) != null) {
                    if (!description.isEmpty() && !description.startsWith("#")) {
                        String ecosystem = mapper.getEcosystem(asCve(description));
                        if (entry.getKey().equals("null")) {
                            assertNull(ecosystem, description);
                        } else {
                            assertEquals(entry.getKey(), ecosystem, description);
                        }
                    }
                }
            }
        }
    }

    @Test
    void testScoring() {
        DescriptionEcosystemMapper mapper = new DescriptionEcosystemMapper();
        String value = "a.cpp b.java c.java";
        assertEquals(JarAnalyzer.DEPENDENCY_ECOSYSTEM, mapper.getEcosystem(asCve(value)));
    }

    @Test
    void testJspLinksDoNotCountScoring() {
        DescriptionEcosystemMapper mapper = new DescriptionEcosystemMapper();
        String value = "Read more at https://domain/help.jsp.";
        assertNull(mapper.getEcosystem(asCve(value)));
    }

    @Test
    void testSubsetFileExtensionsDoNotMatch() {
        DescriptionEcosystemMapper mapper = new DescriptionEcosystemMapper();
        String value = "Read more at index.html."; // i.e. does not match .h
        assertNull(mapper.getEcosystem(asCve(value)));
    }

    @Test
    void testSubsetKeywordsDoNotMatch() {
        DescriptionEcosystemMapper mapper = new DescriptionEcosystemMapper();
        String value = "Wonder if java senses the gc."; // i.e. does not match 'java se'
        assertNull(mapper.getEcosystem(asCve(value)));
    }

    @Test
    void testPhpLinksDoNotCountScoring() {
        DescriptionEcosystemMapper mapper = new DescriptionEcosystemMapper();
        String value = "Read more at https://domain/help.php.";
        assertNull(mapper.getEcosystem(asCve(value)));
    }

    private DefCveItem asCve(String description) {

        List<LangString> descriptions = new ArrayList<>();
        LangString desc = new LangString("en",description);
        descriptions.add(desc);
        CveItem cveItem = new CveItem(null, null, null, null, null, null, null, null, null, null, null, null, null, descriptions, null, null, null, null, null);
        DefCveItem defCveItem = new DefCveItem(cveItem);

        return defCveItem;
    }
}
