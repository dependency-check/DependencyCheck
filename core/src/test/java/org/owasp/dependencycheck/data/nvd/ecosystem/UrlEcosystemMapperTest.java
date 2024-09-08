package org.owasp.dependencycheck.data.nvd.ecosystem;

import io.github.jeremylong.openvulnerability.client.nvd.CveItem;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import io.github.jeremylong.openvulnerability.client.nvd.Reference;
import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;
import org.owasp.dependencycheck.analyzer.PythonPackageAnalyzer;


public class UrlEcosystemMapperTest {

    @Test
    public void testUrlHostEcosystemMapper() {
        
        UrlEcosystemMapper mapper = new UrlEcosystemMapper();
        
        assertEquals(PythonPackageAnalyzer.DEPENDENCY_ECOSYSTEM, mapper.getEcosystem(asCve("https://python.org/path")));
    }

    private DefCveItem asCve(String url) {
        
        List<Reference> references  = new ArrayList<>();
        Reference ref = new Reference(url, null, null);
        references.add(ref);
        CveItem cveItem = new CveItem(null, null, null, null, null, null, null, null, null, null, null, null, null, null, references, null, null, null, null);
        DefCveItem defCveItem = new DefCveItem(cveItem);
        
        return defCveItem;
    }

    @Test
    public void testGetEcosystemMustHandleNullCveReferences() {
        // Given
        UrlEcosystemMapper mapper = new UrlEcosystemMapper();

        CveItem cveItem = new CveItem();
        DefCveItem defCveItem = new DefCveItem(cveItem);

        // When
        String output = mapper.getEcosystem(defCveItem);

        // Then
        assertNull(output);
    }

    @Test
    public void testGetEcosystemMustHandleNullCve() {
        // Given
        UrlEcosystemMapper mapper = new UrlEcosystemMapper();

        DefCveItem cveItem = new DefCveItem();

        // When
        String output = mapper.getEcosystem(cveItem);

        // Then
        assertNull(output);
    }

    @Test
    public void testGetEcosystemMustHandleNullCveItem() {
        // Given
        UrlEcosystemMapper mapper = new UrlEcosystemMapper();

        // When
        String output = mapper.getEcosystem(null);

        // Then
        assertNull(output);
    }
}
