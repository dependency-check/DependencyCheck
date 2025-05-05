package org.owasp.dependencycheck.utils;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PyPACoreMetadataParserTest {

    @Test
    void getProperties_should_throw_exception_for_too_large_major() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PyPACoreMetadataParser.getProperties(new BufferedReader(new StringReader("Metadata-Version: 3.0"))),
                "Expected IllegalArgumentException for too large major in Metadata-Version");
        assertTrue(e.getMessage().contains("Unsupported PyPA Wheel metadata"));
    }

    @Test
    void getProperties_should_properly_parse_multiline_description() throws IOException {
        String payload = "Metadata-Version: 1.0\r\n"
                         + "Description: This is the first line\r\n"
                         + "       | and this the second\r\n"
                         + "       |\r\n"
                         + "       | and the fourth after an empty third\r\n"
                         + "\r\n"
                         + "This: is the body and it is ignored. It may contain an extensive description in various formats";
        Properties props = PyPACoreMetadataParser.getProperties(new BufferedReader(new StringReader(payload)));
        assertEquals("1.0", props.get("Metadata-Version"));
        assertEquals("This is the first line\n"
                            + " and this the second\n"
                            + "\n"
                            + " and the fourth after an empty third", props.get("Description"));
        assertFalse(props.containsKey("This"), "Body was parsed as a header");
    }

    @Test
    void getProperties_should_support_colon_in_headerValue() throws IOException {
        String payload = "Metadata-Version: 2.2\r\n"
                         + "Description: My value contains a : colon\r\n";
        Properties props = PyPACoreMetadataParser.getProperties(new BufferedReader(new StringReader(payload)));
        assertEquals("2.2", props.getProperty("Metadata-Version"));
        assertEquals("My value contains a : colon", props.getProperty("Description"));
    }

    @Test
    void getProperties_should_support_folding_in_headerValue() throws IOException {
        String payload = "Metadata-Version: 2\r\n"
                         + " .2\r\n"
                         + "Description: My value\r\n"
                         + "  contains a \r\n"
                         + " : colon\r\n";
        Properties props = PyPACoreMetadataParser.getProperties(new BufferedReader(new StringReader(payload)));
        assertEquals("2.2", props.getProperty("Metadata-Version"));
        assertEquals("My value contains a : colon", props.getProperty("Description"));
    }

    @Test
    void getProperties_should_support_newer_minors() throws IOException {
        String payload = "Metadata-Version: 2\r\n"
                         + " .5\r\n";
        Properties props = PyPACoreMetadataParser.getProperties(new BufferedReader(new StringReader(payload)));
        assertEquals("2.5", props.getProperty("Metadata-Version"));
    }
}