package org.owasp.dependencycheck.utils;

import org.xml.sax.InputSource;

import java.io.Closeable;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

public class AutoCloseableInputSource extends InputSource implements AutoCloseable {
    public AutoCloseableInputSource(InputStream inputStream) {
        super(inputStream);
    }

    public AutoCloseableInputSource(Reader reader) {
        super(reader);
    }

    @Override
    public void close() throws IOException {
        closeIfNecessary(super.getByteStream());
        closeIfNecessary(super.getCharacterStream());
    }

    private void closeIfNecessary(Closeable closeable) throws IOException {
        if (closeable != null) {
            closeable.close();
        }
    }

    public static AutoCloseableInputSource fromResource(String resourceLocation) throws FileNotFoundException {
        AutoCloseableInputSource inputSource = new AutoCloseableInputSource(new InputStreamReader(FileUtils.getResourceAsStream(resourceLocation), StandardCharsets.UTF_8));
        inputSource.setSystemId(Path.of(resourceLocation).getFileName().toString());
        return inputSource;
    }
}
