package org.owasp.dependencycheck;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.owasp.dependencycheck.analyzer.FileTypeAnalyzer;
import org.owasp.dependencycheck.analyzer.HintAnalyzer;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;

@RunWith(MockitoJUnitRunner.class)
public class AnalysisTaskTest extends BaseTest {

    @Mock
    private FileTypeAnalyzer fileTypeAnalyzer;

    @Mock
    private Dependency dependency;

    @Mock
    private Engine engine;


    @Test
    public void shouldAnalyzeReturnsTrueForNonFileTypeAnalyzers() {
        AnalysisTask instance = new AnalysisTask(new HintAnalyzer(), null, null, null);
        boolean shouldAnalyze = instance.shouldAnalyze();
        assertTrue(shouldAnalyze);
    }

    @Test
    public void shouldAnalyzeReturnsTrueIfTheFileTypeAnalyzersAcceptsTheDependency() {
        final File dependencyFile = new File("");
        when(dependency.getActualFile()).thenReturn(dependencyFile);
        when(fileTypeAnalyzer.accept(dependencyFile)).thenReturn(true);

        AnalysisTask analysisTask = new AnalysisTask(fileTypeAnalyzer, dependency, null, null);

        boolean shouldAnalyze = analysisTask.shouldAnalyze();
        assertTrue(shouldAnalyze);
    }

    @Test
    public void shouldAnalyzeReturnsFalseIfTheFileTypeAnalyzerDoesNotAcceptTheDependency() {
        final File dependencyFile = new File("");
        when(dependency.getActualFile()).thenReturn(dependencyFile);
        when(fileTypeAnalyzer.accept(dependencyFile)).thenReturn(false);

        AnalysisTask analysisTask = new AnalysisTask(fileTypeAnalyzer, dependency, null, null);

        boolean shouldAnalyze = analysisTask.shouldAnalyze();
        assertFalse(shouldAnalyze);
    }

    @Test
    public void taskAnalyzes() throws Exception {
        final AnalysisTask analysisTask = new AnalysisTask(fileTypeAnalyzer, dependency, engine, null);
        when(fileTypeAnalyzer.accept(dependency.getActualFile())).thenReturn(true);

        analysisTask.call();

        verify(fileTypeAnalyzer, times(1)).analyze(dependency, engine);
    }

    @Test
    public void taskDoesNothingIfItShouldNotAnalyze() throws Exception {
        final AnalysisTask analysisTask = new AnalysisTask(fileTypeAnalyzer, dependency, engine, null);
        when(fileTypeAnalyzer.accept(dependency.getActualFile())).thenReturn(false);

        analysisTask.call();

        verify(fileTypeAnalyzer, times(0)).analyze(dependency, engine);
    }
}
