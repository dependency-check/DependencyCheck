package org.owasp.dependencycheck.data.lucene;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.TokenFilter;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.core.KeywordAnalyzer;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public abstract class BaseTokenFilterTest {
    private Analyzer analyzer;

    @BeforeEach
    public void setUp() throws Exception {
        analyzer = new KeywordAnalyzer();
    }

    @AfterEach
    public void tearDown() throws Exception {
        analyzer.close();
    }

    @RepeatedTest(1000)
    public void testRandomStrings() {
        String input = RandomStringUtils.insecure().nextAlphanumeric(1, 1000);
        assertDoesNotThrow(() -> processAllFrom(input), () -> "Failed to process input: " + input);
    }

    protected @NonNull TokenStream freshTokenStream(String input) throws IOException {
        TokenStream dummy = analyzer.tokenStream("dummy", input);
        dummy.reset();
        return dummy;
    }

    @NonNull
    protected List<String> processAllFrom(String input) throws IOException {
        List<String> terms = new ArrayList<>();
        try (TokenFilter filter = newFilter(freshTokenStream(input), terms)) {
            //noinspection StatementWithEmptyBody
            while (filter.incrementToken()) {}
            return terms;
        }
    }

    abstract TokenFilter newFilter(@NonNull final TokenStream stream, List<String> terms);
}
