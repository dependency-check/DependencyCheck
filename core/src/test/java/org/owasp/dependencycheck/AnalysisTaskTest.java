package org.owasp.dependencycheck;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.dependencycheck.analyzer.FileTypeAnalyzer;
import org.owasp.dependencycheck.analyzer.HintAnalyzer;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AnalysisTaskTest extends BaseTest {

    @Mock
    private FileTypeAnalyzer fileTypeAnalyzer;

    @Mock
    private Dependency dependency;

    @Mock
    private Engine engine;


    @Test
    void shouldAnalyzeReturnsTrueForNonFileTypeAnalyzers() {
        AnalysisTask instance = new AnalysisTask(new HintAnalyzer(), null, null, null);
        boolean shouldAnalyze = instance.shouldAnalyze();
        assertTrue(shouldAnalyze);
    }

    @Test
    void shouldAnalyzeReturnsTrueIfTheFileTypeAnalyzersAcceptsTheDependency() {
        final File dependencyFile = new File("");
        when(dependency.getActualFile()).thenReturn(dependencyFile);
        when(fileTypeAnalyzer.accept(dependencyFile)).thenReturn(true);

        AnalysisTask analysisTask = new AnalysisTask(fileTypeAnalyzer, dependency, null, null);

        boolean shouldAnalyze = analysisTask.shouldAnalyze();
        assertTrue(shouldAnalyze);
    }

    @Test
    void shouldAnalyzeReturnsFalseIfTheFileTypeAnalyzerDoesNotAcceptTheDependency() {
        final File dependencyFile = new File("");
        when(dependency.getActualFile()).thenReturn(dependencyFile);
        when(fileTypeAnalyzer.accept(dependencyFile)).thenReturn(false);

        AnalysisTask analysisTask = new AnalysisTask(fileTypeAnalyzer, dependency, null, null);

        boolean shouldAnalyze = analysisTask.shouldAnalyze();
        assertFalse(shouldAnalyze);
    }

    @Test
    void taskAnalyzes() throws Exception {
        final AnalysisTask analysisTask = new AnalysisTask(fileTypeAnalyzer, dependency, engine, null);
        when(fileTypeAnalyzer.accept(dependency.getActualFile())).thenReturn(true);

        analysisTask.call();

        verify(fileTypeAnalyzer, times(1)).analyze(dependency, engine);
    }

    @Test
    void taskDoesNothingIfItShouldNotAnalyze() throws Exception {
        final AnalysisTask analysisTask = new AnalysisTask(fileTypeAnalyzer, dependency, engine, null);
        when(fileTypeAnalyzer.accept(dependency.getActualFile())).thenReturn(false);

        analysisTask.call();

        verify(fileTypeAnalyzer, times(0)).analyze(dependency, engine);
    }
}
