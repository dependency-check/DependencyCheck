package org.owasp.dependencycheck;

import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.matchesPattern;
import static org.mockito.ArgumentMatchers.assertArg;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class PluginLoaderTest {

    private final Instrumentation instrumentation = Mockito.mock(Instrumentation.class);

    @TempDir
    Path tempDir;

    @Test
    void shouldDoNothingIfDirectoryDoesntExist() {
        PluginLoader.premain("blah", instrumentation);
        verifyNoInteractions(instrumentation);
    }

    @Test
    void shouldDoNothingIfDirectoryIsEmpty() {
        PluginLoader.premain(tempDir.toString(), instrumentation);
        verifyNoInteractions(instrumentation);
    }

    @Test
    void shouldAddJarToClassPath() throws Exception {
        createEmptyValidJar();
        createEmptyValidJar();
        PluginLoader.premain(tempDir.toString(), instrumentation);
        verify(instrumentation, times(2))
                .appendToSystemClassLoaderSearch(assertArg(jar -> assertThat(jar.getName(), matchesPattern(".*/dummy.*\\.jar"))));
    }

    @Test
    void shouldStopLoadingPluginsOnBadJarButSucceed() throws Exception {
        PrintStream originalErr = System.err;
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        System.setErr(new PrintStream(errContent));
        try {
            createEmptyBadJar();
            PluginLoader.premain(tempDir.toString(), instrumentation);
            assertThat(errContent.toString(), matchesPattern(Pattern.compile("\\[WARN\\] Failed to read plugin jar file at .*/dummy.*\\.jar\\. Jar will not be available on classpath.*zip file is empty.*", Pattern.DOTALL)));
        } finally {
            System.setErr(originalErr);
        }
    }

    private Path createEmptyBadJar() throws IOException {
        return Files.createTempFile(tempDir, "dummy", ".jar");
    }

    private void createEmptyValidJar() throws IOException {
        new ZipArchiveOutputStream(createEmptyBadJar().toFile()).close();
    }
}