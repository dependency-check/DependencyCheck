package org.owasp.dependencycheck.dependency.naming;

import org.junit.jupiter.api.Test;
import us.springett.parsers.cpe.CpeBuilder;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

import java.net.URLDecoder;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class CpeIdentifierTest {

    @Test
    void testNvdSearchUrlFormatting() throws CpeValidationException {
        String encodedUrl = CpeIdentifier.nvdSearchUrlFor(new CpeBuilder().part(Part.APPLICATION).vendor("apache").product("struts").version("1.9.0").build());
        assertEquals("https://nvd.nist.gov/vuln/search#/nvd/home?sortOrder=3&sortDirection=2&cpeFilterMode=applicability&resultType=records&" +
                "cpeName=cpe%3A2.3%3Aa%3Aapache%3Astruts%3A1.9.0%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A", encodedUrl);
        assertEquals("https://nvd.nist.gov/vuln/search#/nvd/home?sortOrder=3&sortDirection=2&cpeFilterMode=applicability&resultType=records&" +
                "cpeName=cpe:2.3:a:apache:struts:1.9.0:*:*:*:*:*:*:*", URLDecoder.decode(encodedUrl, UTF_8));
    }

    @Test
    void testNvdSearchUrlFormattingEncodesChars() throws CpeValidationException {
        String encodedUrl = CpeIdentifier.nvdSearchUrlFor(new CpeBuilder().part(Part.APPLICATION).vendor("apache$").product("struts$").version("1.9.0$").build());
        assertEquals("https://nvd.nist.gov/vuln/search#/nvd/home?sortOrder=3&sortDirection=2&cpeFilterMode=applicability&resultType=records&" +
                "cpeName=cpe%3A2.3%3Aa%3Aapache%5C%24%3Astruts%5C%24%3A1.9.0%5C%24%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A", encodedUrl);
        assertEquals("https://nvd.nist.gov/vuln/search#/nvd/home?sortOrder=3&sortDirection=2&cpeFilterMode=applicability&resultType=records&" +
                "cpeName=cpe:2.3:a:apache\\$:struts\\$:1.9.0\\$:*:*:*:*:*:*:*", URLDecoder.decode(encodedUrl, UTF_8));
    }

    @Test
    void testNvdProductSearchFormatting() throws CpeValidationException {
        String encodedUrl = CpeIdentifier.nvdProductSearchUrlFor(new CpeBuilder().part(Part.APPLICATION).vendor("apache").product("struts").version("1.9.0").build());
        assertEquals("https://nvd.nist.gov/vuln/search#/nvd/home?sortOrder=3&sortDirection=2&cpeFilterMode=applicability&resultType=records&" +
                "cpeName=cpe%3A2.3%3Aa%3Aapache%3Astruts%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A", encodedUrl);
        assertEquals("https://nvd.nist.gov/vuln/search#/nvd/home?sortOrder=3&sortDirection=2&cpeFilterMode=applicability&resultType=records&" +
                "cpeName=cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*", URLDecoder.decode(encodedUrl, UTF_8));
    }

    @Test
    void testNvdProductSearchUrlFormattingEncodesChars() throws CpeValidationException {
        String encodedUrl = CpeIdentifier.nvdProductSearchUrlFor(new CpeBuilder().part(Part.APPLICATION).vendor("apache$").product("struts$").version("1.9.0$").build());
        assertEquals("https://nvd.nist.gov/vuln/search#/nvd/home?sortOrder=3&sortDirection=2&cpeFilterMode=applicability&resultType=records&" +
                "cpeName=cpe%3A2.3%3Aa%3Aapache%5C%24%3Astruts%5C%24%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A", encodedUrl);
        assertEquals("https://nvd.nist.gov/vuln/search#/nvd/home?sortOrder=3&sortDirection=2&cpeFilterMode=applicability&resultType=records&" +
                "cpeName=cpe:2.3:a:apache\\$:struts\\$:*:*:*:*:*:*:*:*", URLDecoder.decode(encodedUrl, UTF_8));
    }
}