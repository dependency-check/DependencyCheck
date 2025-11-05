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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cpe;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.core.KeywordAnalyzer;
import org.apache.lucene.analysis.miscellaneous.PerFieldAnalyzerWrapper;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.FieldType;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexOptions;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.store.MMapDirectory;
import org.owasp.dependencycheck.data.lucene.SearchFieldAnalyzer;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.utils.Pair;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;

/**
 * <p>
 * An in memory Lucene index that contains the vendor/product combinations from
 * the CPE (application) identifiers within the NVD CVE data.</p>
 *
 * This is the last remaining singleton in dependency-check-core; The use of
 * this singleton - while it may not technically be thread-safe (one database
 * used to build this index may not have the same entries as another) the risk
 * of this is currently believed to be small. As this memory index consumes a
 * large amount of memory we will remain using the singleton pattern for now.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public abstract class AbstractMemoryIndex implements MemoryIndex {

    static {
        // Ensure Lucene uses SLF4J for logging
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();
    }

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractMemoryIndex.class);
    /**
     * The in memory Lucene index.
     */
    private MMapDirectory index;
    /**
     * The Lucene IndexReader.
     */
    private IndexReader indexReader;
    /**
     * The Lucene IndexSearcher.
     */
    private IndexSearcher indexSearcher;
    /**
     * The Lucene Analyzer used for Searching.
     */
    private Analyzer searchingAnalyzer;
    /**
     * The Lucene QueryParser used for Searching.
     */
    private QueryParser queryParser;
    /**
     * The product field analyzer.
     */
    private SearchFieldAnalyzer productFieldAnalyzer;
    /**
     * The vendor field analyzer.
     */
    private SearchFieldAnalyzer vendorFieldAnalyzer;
    /**
     * Track the number of current users of the Lucene index; used to track it
     * it is okay to actually close the index.
     */
    private final AtomicInteger usageCount = new AtomicInteger(0);

    /**
     * Returns a reference to the instance.
     *
     * @return a reference to the instance
     */
    protected abstract AbstractMemoryIndex instance();

    /**
     * Creates and loads data into an in memory index.
     *
     * @param data the CPE data
     * @param settings a reference to the dependency-check settings
     * @throws IndexException thrown if there is an error creating the index
     */
    @Override
    public synchronized void open(Set<Pair<String, String>> data, Settings settings) throws IndexException {
        if (instance().usageCount.addAndGet(1) == 1) {
            try {
                final File temp = settings.getTempDirectory();
                index = new MMapDirectory(temp.toPath());
                buildIndex(data);

                indexReader = DirectoryReader.open(index);
            } catch (IOException ex) {
                throw new IndexException(ex);
            }
            indexSearcher = new IndexSearcher(indexReader);
            searchingAnalyzer = createSearchingAnalyzer();
            queryParser = new QueryParser(Fields.DOCUMENT_KEY, searchingAnalyzer);
        }
    }

    /**
     * returns whether or not the index is open.
     *
     * @return whether or not the index is open
     */
    public synchronized boolean isOpen() {
        return instance().usageCount.get() > 0;
    }

    /**
     * Creates an Analyzer for searching the CPE Index.
     *
     * @return the CPE Analyzer.
     */
    private Analyzer createSearchingAnalyzer() {
        final Map<String, Analyzer> fieldAnalyzers = new HashMap<>();
        fieldAnalyzers.put(Fields.DOCUMENT_KEY, new KeywordAnalyzer());
        productFieldAnalyzer = new SearchFieldAnalyzer();
        vendorFieldAnalyzer = new SearchFieldAnalyzer();
        fieldAnalyzers.put(Fields.PRODUCT, productFieldAnalyzer);
        fieldAnalyzers.put(Fields.VENDOR, vendorFieldAnalyzer);

        return new PerFieldAnalyzerWrapper(new KeywordAnalyzer(), fieldAnalyzers);
    }

    /**
     * Closes the CPE Index.
     */
    @Override
    public synchronized void close() {
        if (instance().usageCount.addAndGet(-1) == 0) {
            if (searchingAnalyzer != null) {
                searchingAnalyzer.close();
                searchingAnalyzer = null;
            }
            if (indexReader != null) {
                try {
                    indexReader.close();
                } catch (IOException ex) {
                    LOGGER.trace("", ex);
                }
                indexReader = null;
            }
            queryParser = null;
            indexSearcher = null;
            if (index != null) {
                try {
                    index.close();
                } catch (IOException ex) {
                    LOGGER.trace("", ex);
                }
                index = null;
            }
        }
    }

    /**
     * Builds the CPE Lucene Index based off of the data within the CveDB.
     *
     * @param data the CPE data
     * @throws IndexException thrown if there is an issue creating the index
     */
    private void buildIndex(Set<Pair<String, String>> data) throws IndexException {
        try (Analyzer analyzer = createSearchingAnalyzer();
                IndexWriter indexWriter = new IndexWriter(index,
                        new IndexWriterConfig(analyzer))) {

            final FieldType ft = new FieldType(TextField.TYPE_STORED);
            //ignore term frequency
            ft.setIndexOptions(IndexOptions.DOCS);
            //ignore field length normalization
            ft.setOmitNorms(true);
            // Tip: reuse the Document and Fields for performance...
            // See "Re-use Document and Field instances" from
            // http://wiki.apache.org/lucene-java/ImproveIndexingSpeed
            final Document doc = new Document();
            final Field v = new Field(Fields.VENDOR, Fields.VENDOR, ft);
            final Field p = new Field(Fields.PRODUCT, Fields.PRODUCT, ft);

            doc.add(v);
            doc.add(p);

            for (Pair<String, String> pair : data) {
                if (pair.getLeft() != null && pair.getRight() != null) {
                    v.setStringValue(pair.getLeft());
                    p.setStringValue(pair.getRight());
                    indexWriter.addDocument(doc);
                    resetAnalyzers();
                }
            }
            indexWriter.commit();

        } catch (DatabaseException ex) {
            LOGGER.debug("", ex);
            throw new IndexException("Error reading CPE data", ex);
        } catch (IOException ex) {
            throw new IndexException("Unable to close an in-memory index", ex);
        }
    }

    /**
     * Searches the index using the given search string.
     *
     * @param searchString the query text
     * @param maxQueryResults the maximum number of documents to return
     * @return the TopDocs found by the search
     * @throws ParseException thrown when the searchString is invalid
     * @throws IndexException thrown when there is an internal error resetting
     * the search analyzer
     * @throws IOException is thrown if there is an issue with the underlying
     * Index
     */
    @Override
    public synchronized TopDocs search(String searchString, int maxQueryResults) throws ParseException, IndexException, IOException {
        final Query query = parseQuery(searchString);
        return search(query, maxQueryResults);
    }

    /**
     * Parses the given string into a Lucene Query.
     *
     * @param searchString the search text
     * @return the Query object
     * @throws ParseException thrown if the search text cannot be parsed
     * @throws IndexException thrown if there is an error resetting the
     * analyzers
     */
    @Override
    public synchronized Query parseQuery(String searchString) throws ParseException, IndexException {
        if (searchString == null || searchString.trim().isEmpty()
                || "product:() AND vendor:()".equals(searchString)) {
            throw new ParseException("Query is null or empty");
        }
        LOGGER.debug(searchString);

        Query query;
        try {
            query = queryParser.parse(searchString);
        } catch (IndexSearcher.TooManyClauses ex) {
            IndexSearcher.setMaxClauseCount(Integer.MAX_VALUE);
            query = queryParser.parse(searchString);
        } catch (ParseException ex) {
            if (ex.getMessage() != null && ex.getMessage().contains("too many boolean clauses")) {
                IndexSearcher.setMaxClauseCount(Integer.MAX_VALUE);
                query = queryParser.parse(searchString);
            } else {
                LOGGER.debug("Parse Exception", ex);
                throw ex;
            }
        }
        try {
            resetAnalyzers();
        } catch (IOException ex) {
            throw new IndexException("Unable to reset the analyzer after parsing", ex);
        }
        return query;
    }

    /**
     * Searches the index using the given query.
     *
     * @param query the query used to search the index
     * @param maxQueryResults the max number of results to return
     * @return the TopDocs found be the query
     * @throws CorruptIndexException thrown if the Index is corrupt
     * @throws IOException thrown if there is an IOException
     */
    @Override
    public synchronized TopDocs search(Query query, int maxQueryResults) throws CorruptIndexException, IOException {
        return indexSearcher.search(query, maxQueryResults);
    }

    /**
     * Retrieves a document from the Index.
     *
     * @param documentId the id of the document to retrieve
     * @return the Document
     * @throws IOException thrown if there is an IOException
     */
    @Override
    public synchronized Document getDocument(int documentId) throws IOException {
        return indexSearcher.storedFields().document(documentId);
    }

    /**
     * Returns the number of CPE entries stored in the index.
     *
     * @return the number of CPE entries stored in the index
     */
    public synchronized int numDocs() {
        if (indexReader == null) {
            return -1;
        }
        return indexReader.numDocs();
    }

    /**
     * Method to explain queries matches.
     *
     * @param query the query used
     * @param doc the document matched
     * @return the explanation
     * @throws IOException thrown if there is an index error
     */
    public synchronized String explain(Query query, int doc) throws IOException {
        return indexSearcher.explain(query, doc).toString();
    }

    /**
     * Common method to reset the searching analyzers.
     *
     * @throws IOException thrown if there is an index error
     */
    protected synchronized void resetAnalyzers() throws IOException {
        productFieldAnalyzer.reset();
        vendorFieldAnalyzer.reset();
    }
}
