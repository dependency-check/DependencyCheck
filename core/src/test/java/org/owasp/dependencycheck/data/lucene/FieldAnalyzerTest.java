/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.lucene;

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.miscellaneous.PerFieldAnalyzerWrapper;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.search.TopScoreDocCollectorManager;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.MMapDirectory;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 *
 * @author Jeremy Long
 */
class FieldAnalyzerTest extends BaseTest {

    @Test
    void testAnalyzers() throws Exception {

        Analyzer analyzer = new SearchFieldAnalyzer();
        File temp = getSettings().getTempDirectory();
        Directory index = new MMapDirectory(temp.toPath());

        String field1 = "product";
        String text1 = "springframework";

        String field2 = "vendor";
        String text2 = "springsource";

        try (IndexWriter w = createIndex(analyzer, index)) {
            addDoc(w, field1, text1, field2, text2);
            text1 = "x-stream";
            text2 = "xstream";
            addDoc(w, field1, text1, field2, text2);
        }

        //Analyzer searchingAnalyzer = new SearchFieldAnalyzer();
        String querystr = "product:\"(Spring Framework Core)\" vendor:(SpringSource)";

        SearchFieldAnalyzer searchAnalyzerProduct = new SearchFieldAnalyzer();
        SearchFieldAnalyzer searchAnalyzerVendor = new SearchFieldAnalyzer();
        HashMap<String, Analyzer> map = new HashMap<>();
        map.put(field1, searchAnalyzerProduct);
        map.put(field2, searchAnalyzerVendor);
        PerFieldAnalyzerWrapper wrapper = new PerFieldAnalyzerWrapper(new StandardAnalyzer(), map);
        QueryParser parser = new QueryParser(field1, wrapper);

        Query q = parser.parse(querystr);

        int hitsPerPage = 10;
        int hitsThreshold = 100;

        IndexReader reader = DirectoryReader.open(index);
        IndexSearcher searcher = new IndexSearcher(reader);
        TopScoreDocCollectorManager manager =
                new TopScoreDocCollectorManager(hitsPerPage, null, hitsThreshold, false);

        TopDocs topDocs = searcher.search(q, manager);
        ScoreDoc[] hits = topDocs.scoreDocs;

        assertEquals(1, hits.length, "Did not find 1 document?");
        assertEquals("springframework", searcher.storedFields().document(hits[0].doc).get(field1));
        assertEquals("springsource", searcher.storedFields().document(hits[0].doc).get(field2));

        querystr = "product:(Apache Struts) vendor:(Apache)";

        reset(searchAnalyzerProduct, searchAnalyzerVendor);
        Query q2 = parser.parse(querystr);
        assertFalse(q2.toString().contains("core"), "second parsing contains previousWord from the TokenPairConcatenatingFilter");

        querystr = "product:(  x-stream^5 )  AND  vendor:(  thoughtworks.xstream )";
        reset(searchAnalyzerProduct, searchAnalyzerVendor);
        Query q3 = parser.parse(querystr);
        manager = new TopScoreDocCollectorManager(hitsPerPage, null, hitsThreshold, false);
        topDocs = searcher.search(q3, manager);
        hits = topDocs.scoreDocs;
        assertEquals("x-stream", searcher.storedFields().document(hits[0].doc).get(field1));
        assertEquals("xstream", searcher.storedFields().document(hits[0].doc).get(field2));
    }

    private IndexWriter createIndex(Analyzer analyzer, Directory index) throws IOException {
        IndexWriterConfig config = new IndexWriterConfig(analyzer);
        return new IndexWriter(index, config);
    }

    private static void addDoc(IndexWriter w, String field1, String text1, String field2, String text2) throws IOException {
        Document doc = new Document();
        doc.add(new TextField(field1, text1, Field.Store.YES));
        doc.add(new TextField(field2, text2, Field.Store.YES));
        w.addDocument(doc);
    }

    private void reset(SearchFieldAnalyzer searchAnalyzerProduct, SearchFieldAnalyzer searchAnalyzerVendor) throws IOException {
        searchAnalyzerProduct.reset();
        searchAnalyzerVendor.reset();
    }
}
