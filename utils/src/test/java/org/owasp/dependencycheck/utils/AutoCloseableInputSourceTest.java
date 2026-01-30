package org.owasp.dependencycheck.utils;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;
import static org.owasp.dependencycheck.utils.AutoCloseableInputSource.fromResource;

class AutoCloseableInputSourceTest {

    @Test
    void fromResourceSetsSystemId() throws Exception {
        try (AutoCloseableInputSource ais = fromResource("schema-validation/simple.xsd")) {
            assertEquals("simple.xsd", ais.getSystemId());
        }
    }

    @Test
    void closeClosesByteStream() throws IOException {
        final AtomicBoolean closed = new AtomicBoolean(false);
        InputStream in = new ByteArrayInputStream(new byte[0]) {
            @Override
            public void close() throws IOException {
                super.close();
                closed.set(true);
            }
        };

        try (AutoCloseableInputSource ais = new AutoCloseableInputSource(in)) {
            assertEquals(0, ais.getByteStream().available());
        }
        assertTrue(closed.get(), "byte stream should be closed");
    }

    @Test
    void closeClosesCharacterStream() throws IOException {
        final AtomicBoolean closed = new AtomicBoolean(false);
        Reader reader = new StringReader("") {
            @Override
            public void close() {
                super.close();
                closed.set(true);
            }
        };

        try (AutoCloseableInputSource ais = new AutoCloseableInputSource(reader)) {
            assertTrue(ais.getCharacterStream().ready(), "character stream should be ready");
        }
        assertTrue(closed.get(), "character stream should be closed");
    }

    @Test
    void closeHandlesNullStreams() throws IOException {
        AutoCloseableInputSource ais1 = new AutoCloseableInputSource((InputStream) null);
        AutoCloseableInputSource ais2 = new AutoCloseableInputSource((Reader) null);
        // should not throw
        ais1.close();
        ais2.close();
    }
}