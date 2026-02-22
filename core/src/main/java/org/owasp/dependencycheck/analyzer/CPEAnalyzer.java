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
package org.owasp.dependencycheck.analyzer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.mutable.MutableInt;
import org.apache.lucene.analysis.CharArraySet;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopDocs;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.cpe.CpeMemoryIndex;
import org.owasp.dependencycheck.data.cpe.Fields;
import org.owasp.dependencycheck.data.cpe.IndexEntry;
import org.owasp.dependencycheck.data.cpe.IndexException;
import org.owasp.dependencycheck.data.cpe.MemoryIndex;
import org.owasp.dependencycheck.data.lucene.LuceneUtils;
import org.owasp.dependencycheck.data.lucene.SearchFieldAnalyzer;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.update.cpe.CpePlus;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeBuilder;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

/**
 * CPEAnalyzer is a utility class that takes a project dependency and attempts
 * to discern if there is an associated CPE. It uses the evidence contained
 * within the dependency to search the Lucene index.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class CPEAnalyzer extends AbstractAnalyzer {

    /**
     * The Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CPEAnalyzer.class);
    /**
     * The weighting boost to give terms when constructing the Lucene query.
     */
    private static final int WEIGHTING_BOOST = 1;
    /**
     * A string representation of a regular expression defining characters
     * utilized within the CPE Names. Note, the :/ are included so URLs are
     * passed into the Lucene query so that the specialized tokenizer can parse
     * them.
     */
    private static final String CLEANSE_CHARACTER_RX = "[^A-Za-z0-9 ._:/-]";
    /**
     * A string representation of a regular expression used to remove all but
     * alpha characters.
     */
    private static final String CLEANSE_NONALPHA_RX = "[^A-Za-z]*";

    /**
     * The CPE in memory index.
     */
    private MemoryIndex cpe;
    /**
     * The CVE Database.
     */
    private CveDB cve;
    /**
     * A reference to the ODC engine.
     */
    private Engine engine;
    /**
     * The list of ecosystems to skip during analysis. These are skipped because
     * there is generally a more accurate vulnerability analyzer in the
     * pipeline.
     */
    private List<String> skipEcosystems;
    /**
     * A reference to the ecosystem object; used to obtain the max query results
     * for each ecosystem.
     */
    private Ecosystem ecosystemTools;
    /**
     * A reference to the suppression analyzer; for timing reasons we need to
     * test for suppressions immediately after identifying the match because a
     * higher confidence match on a FP can mask a lower confidence, yet valid
     * match.
     */
    private CpeSuppressionAnalyzer suppression;

    /**
     * Returns the name of this analyzer.
     *
     * @return the name of this analyzer.
     */
    @Override
    public String getName() {
        return "CPE Analyzer";
    }

    /**
     * Returns the analysis phase that this analyzer should run in.
     *
     * @return the analysis phase that this analyzer should run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.IDENTIFIER_ANALYSIS;
    }

    /**
     * Creates the CPE Lucene Index.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException is thrown if there is an issue opening
     * the index.
     */
    @Override
    public void prepareAnalyzer(Engine engine) throws InitializationException {
        super.prepareAnalyzer(engine);
        this.engine = engine;
        try {
            this.open(engine.getDatabase());
        } catch (IOException ex) {
            LOGGER.debug("Exception initializing the Lucene Index", ex);
            throw new InitializationException("An exception occurred initializing the Lucene Index", ex);
        } catch (DatabaseException ex) {
            LOGGER.debug("Exception accessing the database", ex);
            throw new InitializationException("An exception occurred accessing the database", ex);
        }
        final String[] tmp = engine.getSettings().getArray(Settings.KEYS.ECOSYSTEM_SKIP_CPEANALYZER);
        if (tmp == null) {
            skipEcosystems = new ArrayList<>();
        } else {
            LOGGER.debug("Skipping CPE Analysis for {}", StringUtils.join(tmp, ","));
            skipEcosystems = Arrays.asList(tmp);
        }
        ecosystemTools = new Ecosystem(engine.getSettings());
        suppression = new CpeSuppressionAnalyzer();
        suppression.initialize(engine.getSettings());
        suppression.prepareAnalyzer(engine);
    }

    /**
     * Opens the data source.
     *
     * @param cve a reference to the NVD CVE database
     * @throws IOException when the Lucene directory to be queried does not
     * exist or is corrupt.
     * @throws DatabaseException when the database throws an exception. This
     * usually occurs when the database is in use by another process.
     */
    public void open(CveDB cve) throws IOException, DatabaseException {
        this.cve = cve;
        this.cpe = CpeMemoryIndex.getInstance();
        try {
            final long creationStart = System.currentTimeMillis();
            cpe.open(cve.getVendorProductList(), this.getSettings());
            final long creationSeconds = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis() - creationStart);
            LOGGER.info("Created CPE Index ({} seconds)", creationSeconds);
        } catch (IndexException ex) {
            LOGGER.debug("IndexException", ex);
            throw new DatabaseException(ex);
        }
    }

    /**
     * Closes the data sources.
     */
    @Override
    public void closeAnalyzer() {
        if (cpe != null) {
            cpe.close();
            cpe = null;
        }
    }

    /**
     * Searches the data store of CPE entries, trying to identify the CPE for
     * the given dependency based on the evidence contained within. The
     * dependency passed in is updated with any identified CPE values.
     *
     * @param dependency the dependency to search for CPE entries on
     * @throws CorruptIndexException is thrown when the Lucene index is corrupt
     * @throws IOException is thrown when an IOException occurs
     * @throws ParseException is thrown when the Lucene query cannot be parsed
     * @throws AnalysisException thrown if the suppression rules failed
     */
    protected void determineCPE(Dependency dependency) throws CorruptIndexException, IOException, ParseException, AnalysisException {
        boolean identifierAdded;

        final Set<String> majorVersions = dependency.getSoftwareIdentifiers()
                .stream()
                .filter(i -> i instanceof PurlIdentifier)
                .map(i -> {
                    final PurlIdentifier p = (PurlIdentifier) i;
                    final DependencyVersion depVersion = DependencyVersionUtil.parseVersion(p.getVersion(), false);
                    if (depVersion != null) {
                        return depVersion.getVersionParts().get(0);
                    }
                    return null;
                }).collect(Collectors.toSet());

        final Map<String, MutableInt> vendors = new HashMap<>();
        final Map<String, MutableInt> products = new HashMap<>();
        final Set<Integer> previouslyFound = new HashSet<>();

        for (Confidence confidence : Confidence.values()) {
            collectTerms(vendors, dependency.getIterator(EvidenceType.VENDOR, confidence));
            LOGGER.trace("vendor search: {}", vendors);
            collectTerms(products, dependency.getIterator(EvidenceType.PRODUCT, confidence));
            addMajorVersionToTerms(majorVersions, products);
            LOGGER.trace("product search: {}", products);
            if (!vendors.isEmpty() && !products.isEmpty()) {
                final List<IndexEntry> entries = searchCPE(vendors, products,
                        dependency.getVendorWeightings(), dependency.getProductWeightings(),
                        dependency.getEcosystem());
                if (entries == null) {
                    continue;
                }

                identifierAdded = false;
                for (IndexEntry e : entries) {
                    if (previouslyFound.contains(e.getDocumentId()) /*|| (filter > 0 && e.getSearchScore() < filter)*/) {
                        continue;
                    }
                    previouslyFound.add(e.getDocumentId());
                    if (verifyEntry(e, dependency, majorVersions)) {
                        final String vendor = e.getVendor();
                        final String product = e.getProduct();
                        LOGGER.trace("identified vendor/product: {}/{}", vendor, product);
                        identifierAdded |= determineIdentifiers(dependency, vendor, product, confidence);
                    }
                }
                if (identifierAdded) {
                    break;
                }
            }
        }
    }

    /**
     * <p>
     * Returns the text created by concatenating the text and the values from
     * the EvidenceCollection (filtered for a specific confidence). This
     * attempts to prevent duplicate terms from being added.</p>
     * <p>
     * Note, if the evidence is longer then 1000 characters it will be
     * truncated.</p>
     *
     * @param terms the collection of terms
     * @param evidence an iterable set of evidence to concatenate
     */
    @SuppressWarnings("null")

    protected void collectTerms(Map<String, MutableInt> terms, Iterable<Evidence> evidence) {
        for (Evidence e : evidence) {
            String value = cleanseText(e.getValue());
            if (StringUtils.isBlank(value)) {
                continue;
            }
            if (value.length() > 1000) {
                boolean trimmed = false;
                int pos = value.lastIndexOf(" ", 1000);
                if (pos > 0) {
                    value = value.substring(0, pos);
                    trimmed = true;
                } else {
                    pos = value.lastIndexOf(".", 1000);
                }
                if (!trimmed) {
                    if (pos > 0) {
                        value = value.substring(0, pos);
                        trimmed = true;
                    } else {
                        pos = value.lastIndexOf("-", 1000);
                    }
                }
                if (!trimmed) {
                    if (pos > 0) {
                        value = value.substring(0, pos);
                        trimmed = true;
                    } else {
                        pos = value.lastIndexOf("_", 1000);
                    }
                }
                if (!trimmed) {
                    if (pos > 0) {
                        value = value.substring(0, pos);
                        trimmed = true;
                    } else {
                        pos = value.lastIndexOf("/", 1000);
                    }
                }
                if (!trimmed && pos > 0) {
                    value = value.substring(0, pos);
                    trimmed = true;
                }
                if (!trimmed) {
                    value = value.substring(0, 1000);
                }
            }
            addTerm(terms, value);
        }
    }

    private void addMajorVersionToTerms(Set<String> majorVersions, Map<String, MutableInt> products) {
        final Map<String, MutableInt> temp = new HashMap<>();
        products.entrySet().stream()
                .filter(term -> term.getKey() != null)
                .forEach(term -> majorVersions.stream()
                .filter(version -> version != null
                && (!term.getKey().endsWith(version)
                && !Character.isDigit(term.getKey().charAt(term.getKey().length() - 1))
                && !products.containsKey(term.getKey() + version)))
                .forEach(version -> {
                    addTerm(temp, term.getKey() + version);
                }));
        products.entrySet().stream()
                .filter(term -> term.getKey() != null)
                .forEach(term -> majorVersions.stream()
                .filter(Objects::nonNull)
                .map(version -> "v" + version)
                .filter(version -> (!term.getKey().endsWith(version)
                && !Character.isDigit(term.getKey().charAt(term.getKey().length() - 1))
                && !products.containsKey(term.getKey() + version)))
                .forEach(version -> {
                    addTerm(temp, term.getKey() + version);
                }));
        products.putAll(temp);
    }

    /**
     * Adds a term to the map of terms.
     *
     * @param terms the map of terms
     * @param value the value of the term to add
     */
    private void addTerm(Map<String, MutableInt> terms, String value) {
        final MutableInt count = terms.get(value);
        if (count == null) {
            terms.put(value, new MutableInt(1));
        } else {
            count.add(1);
        }
    }

    /**
     * <p>
     * Searches the Lucene CPE index to identify possible CPE entries associated
     * with the supplied vendor, product, and version.</p>
     *
     * <p>
     * If either the vendorWeightings or productWeightings lists have been
     * populated this data is used to add weighting factors to the search.</p>
     *
     * @param vendor the text used to search the vendor field
     * @param product the text used to search the product field
     * @param vendorWeightings a list of strings to use to add weighting factors
     * to the vendor field
     * @param productWeightings Adds a list of strings that will be used to add
     * weighting factors to the product search
     * @param ecosystem the dependency's ecosystem
     * @return a list of possible CPE values
     */
    protected List<IndexEntry> searchCPE(Map<String, MutableInt> vendor, Map<String, MutableInt> product,
            Set<String> vendorWeightings, Set<String> productWeightings, String ecosystem) {

        final int maxQueryResults = ecosystemTools.getLuceneMaxQueryLimitFor(ecosystem);
        final List<IndexEntry> ret = new ArrayList<>(maxQueryResults);

        final String searchString = buildSearch(vendor, product, vendorWeightings, productWeightings);
        if (searchString == null) {
            return ret;
        }
        try {
            final Query query = cpe.parseQuery(searchString);
            final TopDocs docs = cpe.search(query, maxQueryResults);

            for (ScoreDoc d : docs.scoreDocs) {
                //if (d.score >= minLuceneScore) {
                final Document doc = cpe.getDocument(d.doc);
                final IndexEntry entry = new IndexEntry();
                entry.setDocumentId(d.doc);
                entry.setVendor(doc.get(Fields.VENDOR));
                entry.setProduct(doc.get(Fields.PRODUCT));
                entry.setSearchScore(d.score);

//                LOGGER.error("Explanation: ---------------------");
//                LOGGER.error("Explanation: " + entry.getVendor() + " " + entry.getProduct() + " " + entry.getSearchScore());
//                LOGGER.error("Explanation: " + searchString);
//                LOGGER.error("Explanation: " + cpe.explain(query, d.doc));
                if (!ret.contains(entry)) {
                    ret.add(entry);
                }
                //}
            }
            return ret;
        } catch (ParseException ex) {
            LOGGER.warn("An error occurred querying the CPE data. See the log for more details.");
            LOGGER.info("Unable to parse: {}", searchString, ex);
        } catch (IndexException ex) {
            LOGGER.warn("An error occurred resetting the CPE index searcher. See the log for more details.");
            LOGGER.info("Unable to reset the search analyzer", ex);
        } catch (IOException ex) {
            LOGGER.warn("An error occurred reading CPE data. See the log for more details.");
            LOGGER.info("IO Error with search string: {}", searchString, ex);
        }
        return null;
    }

    /**
     * <p>
     * Builds a Lucene search string by properly escaping data and constructing
     * a valid search query.</p>
     *
     * <p>
     * If either the possibleVendor or possibleProducts lists have been
     * populated this data is used to add weighting factors to the search string
     * generated.</p>
     *
     * @param vendor text to search the vendor field
     * @param product text to search the product field
     * @param vendorWeighting a list of strings to apply to the vendor to boost
     * the terms weight
     * @param productWeightings a list of strings to apply to the product to
     * boost the terms weight
     * @return the Lucene query
     */
    protected String buildSearch(Map<String, MutableInt> vendor, Map<String, MutableInt> product,
            Set<String> vendorWeighting, Set<String> productWeightings) {

        final StringBuilder sb = new StringBuilder();

        if (!appendWeightedSearch(sb, Fields.PRODUCT, product, productWeightings)) {
            return null;
        }
        sb.append(" AND ");
        if (!appendWeightedSearch(sb, Fields.VENDOR, vendor, vendorWeighting)) {
            return null;
        }
        return sb.toString();
    }

    /**
     * This method constructs a Lucene query for a given field. The searchText
     * is split into separate words and if the word is within the list of
     * weighted words then an additional weighting is applied to the term as it
     * is appended into the query.
     *
     * @param sb a StringBuilder that the query text will be appended to.
     * @param field the field within the Lucene index that the query is
     * searching.
     * @param terms text used to construct the query.
     * @param weightedText a list of terms that will be considered higher
     * importance when searching.
     * @return if the append was successful.
     */
    @SuppressWarnings("StringSplitter")
    private boolean appendWeightedSearch(StringBuilder sb, String field, Map<String, MutableInt> terms, Set<String> weightedText) {
        if (terms.isEmpty()) {
            return false;
        }
        sb.append(field).append(":(");
        boolean addSpace = false;
        boolean addedTerm = false;

        for (Map.Entry<String, MutableInt> entry : terms.entrySet()) {
            final StringBuilder boostedTerms = new StringBuilder();
            final int weighting = entry.getValue().intValue();
            final String[] text = entry.getKey().split(" ");
            for (String word : text) {
                if (word.isEmpty()) {
                    continue;
                }
                if (addSpace) {
                    sb.append(" ");
                } else {
                    addSpace = true;
                }
                addedTerm = true;
                if (LuceneUtils.isKeyword(word)) {
                    sb.append("\"");
                    LuceneUtils.appendEscapedLuceneQuery(sb, word);
                    sb.append("\"");
                } else {
                    LuceneUtils.appendEscapedLuceneQuery(sb, word);
                }
                final String boostTerm = findBoostTerm(word, weightedText);

                //The weighting is on a full phrase rather then at a term level for vendor or products
                //TODO - should the weighting be at a "word" level as opposed to phrase level? Or combined word and phrase?
                //remember the reason we are counting the frequency of "phrases" as opposed to terms is that
                //we need to keep the correct sequence of terms from the evidence so the term concatenating analyzer
                //works correctly and will causes searches to take spring framework and produce: spring springframework framework
                if (boostTerm != null) {
                    sb.append("^").append(weighting + WEIGHTING_BOOST);
                    if (!boostTerm.equals(word)) {
                        boostedTerms.append(" ");
                        LuceneUtils.appendEscapedLuceneQuery(boostedTerms, boostTerm);
                        boostedTerms.append("^").append(weighting + WEIGHTING_BOOST);
                    }
                } else if (weighting > 1) {
                    sb.append("^").append(weighting);
                }
            }
            if (boostedTerms.length() > 0) {
                sb.append(boostedTerms);
            }
        }
        sb.append(")");
        return addedTerm;
    }

    /**
     * Removes characters from the input text that are not used within the CPE
     * index.
     *
     * @param text is the text to remove the characters from.
     * @return the text having removed some characters.
     */
    private String cleanseText(String text) {
        return text.replaceAll(CLEANSE_CHARACTER_RX, " ");
    }

    /**
     * Searches the collection of boost terms for the given term. The elements
     * are case insensitive matched using only the alphanumeric contents of the
     * terms; all other characters are removed.
     *
     * @param term the term to search for
     * @param boost the collection of boost terms
     * @return the value identified
     */
    private String findBoostTerm(String term, Set<String> boost) {
        for (String entry : boost) {
            if (equalsIgnoreCaseAndNonAlpha(term, entry)) {
                return entry;
            }
        }
        return null;
    }

    /**
     * Compares two strings after lower casing them and removing the non-alpha
     * characters.
     *
     * @param l string one to compare.
     * @param r string two to compare.
     * @return whether or not the two strings are similar.
     */
    private boolean equalsIgnoreCaseAndNonAlpha(String l, String r) {
        if (l == null || r == null) {
            return false;
        }

        final String left = l.replaceAll(CLEANSE_NONALPHA_RX, "");
        final String right = r.replaceAll(CLEANSE_NONALPHA_RX, "");
        return left.equalsIgnoreCase(right);
    }

    /**
     * Ensures that the CPE Identified matches the dependency. This validates
     * that the product, vendor, and version information for the CPE are
     * contained within the dependencies evidence.
     *
     * @param entry a CPE entry
     * @param dependency the dependency that the CPE entries could be for
     * @param majorVersions the major versions detected for the dependency
     * @return whether or not the entry is valid.
     */
    private boolean verifyEntry(final IndexEntry entry, final Dependency dependency,
            final Set<String> majorVersions) {
        boolean isValid = false;
        //TODO - does this nullify some of the fuzzy matching that happens in the lucene search?
        // for instance CPE some-component and in the evidence we have SomeComponent.

        //TODO - should this have a package manager only flag instead of just looking for NPM
        if (Ecosystem.NODEJS.equals(dependency.getEcosystem())) {
            for (Identifier i : dependency.getSoftwareIdentifiers()) {
                if (i instanceof PurlIdentifier) {
                    final PurlIdentifier p = (PurlIdentifier) i;
                    if (cleanPackageName(p.getName()).equals(cleanPackageName(entry.getProduct()))) {
                        isValid = true;
                    }
                }
            }
        } else if (collectionContainsString(dependency.getEvidence(EvidenceType.VENDOR), entry.getVendor())) {
            if (collectionContainsString(dependency.getEvidence(EvidenceType.PRODUCT), entry.getProduct())) {
                isValid = true;
            } else {
                isValid = majorVersions.stream().filter(version
                        -> version != null && entry.getProduct().endsWith("v" + version) && entry.getProduct().length() > version.length() + 1)
                        .anyMatch(version
                                -> collectionContainsString(dependency.getEvidence(EvidenceType.PRODUCT),
                                entry.getProduct().substring(0, entry.getProduct().length() - version.length() - 1))
                        );
                isValid |= majorVersions.stream().filter(version
                        -> version != null && entry.getProduct().endsWith(version) && entry.getProduct().length() > version.length())
                        .anyMatch(version
                                -> collectionContainsString(dependency.getEvidence(EvidenceType.PRODUCT),
                                entry.getProduct().substring(0, entry.getProduct().length() - version.length()))
                        );
            }
        }
        return isValid;
    }

    /**
     * Only returns alpha numeric characters contained in a given package name.
     *
     * @param name the package name to cleanse
     * @return the cleansed package name
     */
    private String cleanPackageName(String name) {
        if (name == null) {
            return "";
        }
        return name.replaceAll("[^a-zA-Z0-9]+", "");
    }

    /**
     * Used to determine if the EvidenceCollection contains a specific string.
     *
     * @param evidence an of evidence object to check
     * @param text the text to search for
     * @return whether or not the EvidenceCollection contains the string
     */
    @SuppressWarnings("StringSplitter")
    private boolean collectionContainsString(Set<Evidence> evidence, String text) {
        //TODO - likely need to change the split... not sure if this will work for CPE with special chars
        if (text == null) {
            return false;
        }
        // Check if we have an exact match
        final String textLC = text.toLowerCase();
        for (Evidence e : evidence) {
            if (e.getValue().toLowerCase().equals(textLC)) {
                return true;
            }
        }

        final String[] words = text.split("[\\s_-]+");
        final List<String> list = new ArrayList<>();
        String tempWord = null;
        final CharArraySet stopWords = SearchFieldAnalyzer.getStopWords();
        for (String word : words) {
            /*
             single letter words should be concatenated with the next word.
             so { "m", "core", "sample" } -> { "mcore", "sample" }
             */
            if (tempWord != null) {
                list.add(tempWord + word);
                tempWord = null;
            } else if (word.length() <= 2) {
                tempWord = word;
            } else {
                if (stopWords.contains(word)) {
                    continue;
                }
                list.add(word);
            }
        }
        if (tempWord != null) {
            if (!list.isEmpty()) {
                final String tmp = list.get(list.size() - 1) + tempWord;
                list.add(tmp);
            } else {
                list.add(tempWord);
            }
        }
        if (list.isEmpty()) {
            return false;
        }
        boolean isValid = true;

        // Prepare the evidence values, e.g. remove the characters we used for splitting
        final List<String> evidenceValues = new ArrayList<>(evidence.size());
        evidence.forEach((e) -> evidenceValues.add(e.getValue().toLowerCase().replaceAll("[\\s_-]+", "")));

        for (String word : list) {
            word = word.toLowerCase();
            boolean found = false;
            for (String e : evidenceValues) {
                if (e.contains(word)) {
                    if ("http".equals(word) && e.contains("http:")) {
                        continue;
                    }
                    found = true;
                    break;
                }
            }
            isValid &= found;
        }
        return isValid;
    }

    /**
     * Analyzes a dependency and attempts to determine if there are any CPE
     * identifiers for this dependency.
     *
     * @param dependency The Dependency to analyze.
     * @param engine The analysis engine
     * @throws AnalysisException is thrown if there is an issue analyzing the
     * dependency.
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (skipEcosystems.contains(dependency.getEcosystem())) {
            return;
        }
        try {
            determineCPE(dependency);
        } catch (CorruptIndexException ex) {
            throw new AnalysisException("CPE Index is corrupt.", ex);
        } catch (IOException ex) {
            throw new AnalysisException("Failure opening the CPE Index.", ex);
        } catch (ParseException ex) {
            throw new AnalysisException("Unable to parse the generated Lucene query for this dependency.", ex);
        }
    }

    /**
     * Retrieves a list of CPE values from the CveDB based on the vendor and
     * product passed in. The list is then validated to find only CPEs that are
     * valid for the given dependency. It is possible that the CPE identified is
     * a best effort "guess" based on the vendor, product, and version
     * information.
     *
     * @param dependency the Dependency being analyzed
     * @param vendor the vendor for the CPE being analyzed
     * @param product the product for the CPE being analyzed
     * @param currentConfidence the current confidence being used during
     * analysis
     * @return <code>true</code> if an identifier was added to the dependency;
     * otherwise <code>false</code>
     * @throws AnalysisException thrown if the suppression rules failed
     */
    @SuppressWarnings("StringSplitter")
    protected boolean determineIdentifiers(Dependency dependency, String vendor, String product,
            Confidence currentConfidence) throws AnalysisException {

        final CpeBuilder cpeBuilder = new CpeBuilder();

        final Set<CpePlus> cpePlusEntries = cve.getCPEs(vendor, product);
        final Set<Cpe> cpes = filterEcosystem(dependency.getEcosystem(), cpePlusEntries);
        if (cpes == null || cpes.isEmpty()) {
            return false;
        }

        DependencyVersion bestGuess;
        if ("Golang".equals(dependency.getEcosystem()) && dependency.getVersion() == null) {
            bestGuess = new DependencyVersion("*");
        } else {
            bestGuess = new DependencyVersion("-");
        }
        String bestGuessUpdate = null;
        Confidence bestGuessConf = null;
        String bestGuessURL = null;
        final Set<IdentifierMatch> collected = new HashSet<>();

        considerDependencyVersion(dependency, vendor, product, currentConfidence, collected);

        //TODO the following algorithm incorrectly identifies things as a lower version
        // if there lower confidence evidence when the current (highest) version number
        // is newer then anything in the NVD.
        for (Confidence conf : Confidence.values()) {
            for (Evidence evidence : dependency.getIterator(EvidenceType.VERSION, conf)) {
                final DependencyVersion evVer = DependencyVersionUtil.parseVersion(evidence.getValue(), true);
                if (evVer == null) {
                    continue;
                }
                DependencyVersion evBaseVer = null;
                String evBaseVerUpdate = null;
                final int idx = evVer.getVersionParts().size() - 1;
                if (evVer.getVersionParts().get(idx)
                        .matches("^(v|release|final|snapshot|beta|alpha|u|rc|m|20\\d\\d).*$")) {
                    //store the update version
                    final String checkUpdate = evVer.getVersionParts().get(idx);
                    if (checkUpdate.matches("^(v|release|final|snapshot|beta|alpha|u|rc|m|20\\d\\d).*$")) {
                        evBaseVerUpdate = checkUpdate;
                        evBaseVer = new DependencyVersion();
                        evBaseVer.setVersionParts(evVer.getVersionParts().subList(0, idx));
                    }
                }
                //TODO - review and update for new JSON data
                for (Cpe vs : cpes) {
                    final DependencyVersion dbVer = DependencyVersionUtil.parseVersion(vs.getVersion());
                    DependencyVersion dbVerUpdate = dbVer;
                    if (vs.getUpdate() != null && !vs.getUpdate().isEmpty() && !vs.getUpdate().startsWith("*") && !vs.getUpdate().startsWith("-")) {
                        dbVerUpdate = DependencyVersionUtil.parseVersion(vs.getVersion() + '.' + vs.getUpdate(), true);
                    }
                    if (dbVer == null) { //special case, no version specified - everything is vulnerable
                        final String url = CpeIdentifier.nvdProductSearchUrlFor(vs);
                        final IdentifierMatch match = new IdentifierMatch(vs, url, IdentifierConfidence.BROAD_MATCH, conf);
                        collected.add(match);
                    } else if (evVer.equals(dbVer)) {
                        addExactMatch(vs, evBaseVerUpdate, conf, collected);
                    } else if (evBaseVer != null && evBaseVer.equals(dbVer)
                            && (bestGuessConf == null || bestGuessConf.compareTo(conf) > 0)) {
                        bestGuessConf = conf;
                        bestGuess = dbVer;
                        bestGuessUpdate = evBaseVerUpdate;
                        bestGuessURL = CpeIdentifier.nvdSearchUrlFor(vs);
                    } else if (dbVerUpdate != null && evVer.getVersionParts().size() <= dbVerUpdate.getVersionParts().size()
                            && evVer.matchesAtLeastThreeLevels(dbVerUpdate)) {
                        if (bestGuessConf == null || bestGuessConf.compareTo(conf) > 0) {
                            if (bestGuess.getVersionParts().size() < dbVer.getVersionParts().size()) {
                                bestGuess = dbVer;
                                bestGuessUpdate = evBaseVerUpdate;
                                bestGuessConf = conf;
                            }
                        }
                    }
                }
                if ((bestGuessConf == null || bestGuessConf.compareTo(conf) > 0)
                        && bestGuess.getVersionParts().size() < evVer.getVersionParts().size()) {
                    bestGuess = evVer;
                    bestGuessUpdate = evBaseVerUpdate;
                    bestGuessConf = conf;
                }
            }
        }

        cpeBuilder.part(Part.APPLICATION).vendor(vendor).product(product);
        final int idx = bestGuess.getVersionParts().size() - 1;
        if (bestGuess.getVersionParts().get(idx)
                .matches("^(v|release|final|snapshot|beta|alpha|u|rc|m|20\\d\\d).*$")) {
            cpeBuilder.version(StringUtils.join(bestGuess.getVersionParts().subList(0, idx), "."));
            //when written - no update versions in the NVD start with v### - they all strip the v off
            if (bestGuess.getVersionParts().get(idx).matches("^v\\d.*$")) {
                cpeBuilder.update(bestGuess.getVersionParts().get(idx).substring(1));
            } else {
                cpeBuilder.update(bestGuess.getVersionParts().get(idx));
            }
        } else {
            cpeBuilder.version(bestGuess.toString());
            if (bestGuessUpdate != null) {
                cpeBuilder.update(bestGuessUpdate);
            }
        }
        final Cpe guessCpe;

        try {
            guessCpe = cpeBuilder.build();
        } catch (CpeValidationException ex) {
            throw new AnalysisException(String.format("Unable to create a CPE for %s:%s:%s", vendor, product, bestGuess));
        }
        if (!"-".equals(guessCpe.getVersion())) {
            String url = null;
            if (bestGuessURL != null) {
                url = bestGuessURL;
            }
            if (bestGuessConf == null) {
                bestGuessConf = Confidence.LOW;
            }
            final IdentifierMatch match = new IdentifierMatch(guessCpe, url, IdentifierConfidence.BEST_GUESS, bestGuessConf);

            collected.add(match);
        }
        boolean identifierAdded = false;
        if (!collected.isEmpty()) {
            final List<IdentifierMatch> items = new ArrayList<>(collected);

            Collections.sort(items);
            final IdentifierConfidence bestIdentifierQuality = items.get(0).getIdentifierConfidence();
            final Confidence bestEvidenceQuality = items.get(0).getEvidenceConfidence();
            boolean addedNonGuess = false;
            final Confidence prevAddedConfidence = dependency.getVulnerableSoftwareIdentifiers().stream().map(Identifier::getConfidence)
                    .min(Comparator.comparing(Confidence::ordinal))
                    .orElse(Confidence.LOW);

            for (IdentifierMatch m : items) {
                if (bestIdentifierQuality.equals(m.getIdentifierConfidence())
                        && bestEvidenceQuality.equals(m.getEvidenceConfidence())) {
                    final CpeIdentifier i = m.getIdentifier();
                    if (bestIdentifierQuality == IdentifierConfidence.BEST_GUESS) {
                        if (addedNonGuess) {
                            continue;
                        }
                        i.setConfidence(Confidence.LOW);
                    } else {
                        i.setConfidence(bestEvidenceQuality);
                    }
                    if (prevAddedConfidence.compareTo(i.getConfidence()) < 0) {
                        continue;
                    }

                    //TODO - while this gets the job down it is slow; consider refactoring
                    dependency.addVulnerableSoftwareIdentifier(i);
                    suppression.analyze(dependency, engine);
                    if (dependency.getVulnerableSoftwareIdentifiers().contains(i)) {
                        identifierAdded = true;
                        if (!addedNonGuess && bestIdentifierQuality != IdentifierConfidence.BEST_GUESS) {
                            addedNonGuess = true;
                        }
                    }
                }
            }
        }
        return identifierAdded;
    }

    /**
     * Adds a new CPE to the identifier match collection.
     *
     * @param vs a reference to the vulnerable software
     * @param updateVersion the update version
     * @param conf the current confidence
     * @param collected a reference to the collected identifiers
     */
    private void addExactMatch(Cpe vs, String updateVersion, Confidence conf,
            final Set<IdentifierMatch> collected) {

        final CpeBuilder cpeBuilder = new CpeBuilder();
        final String url = CpeIdentifier.nvdSearchUrlFor(vs);
        Cpe useCpe;
        if (updateVersion != null && "*".equals(vs.getUpdate())) {
            try {
                useCpe = cpeBuilder.part(vs.getPart()).wfVendor(vs.getWellFormedVendor())
                        .wfProduct(vs.getWellFormedProduct()).wfVersion(vs.getWellFormedVersion())
                        .wfEdition(vs.getWellFormedEdition()).wfLanguage(vs.getWellFormedLanguage())
                        .wfOther(vs.getWellFormedOther()).wfSwEdition(vs.getWellFormedSwEdition())
                        .update(updateVersion).build();
            } catch (CpeValidationException ex) {
                LOGGER.debug("Error building cpe with update:" + updateVersion, ex);
                useCpe = vs;
            }
        } else {
            useCpe = vs;
        }
        final IdentifierMatch match = new IdentifierMatch(useCpe, url, IdentifierConfidence.EXACT_MATCH, conf);
        collected.add(match);
    }

    /**
     * Evaluates whether or not to use the `version` of the dependency instead
     * of the version evidence. The dependency should not always be used as it
     * can cause FP.
     *
     * @param dependency the dependency being analyzed
     * @param product the product name
     * @param vendor the vendor name
     * @param confidence the current confidence level
     * @param collected a reference to the identifiers matched
     * @throws AnalysisException thrown if aliens attacked and valid input could
     * not be used to construct a CPE
     */
    private void considerDependencyVersion(Dependency dependency,
            String vendor, String product, Confidence confidence,
            final Set<IdentifierMatch> collected)
            throws AnalysisException {

        if (dependency.getVersion() != null && !dependency.getVersion().isEmpty()) {
            final CpeBuilder cpeBuilder = new CpeBuilder();
            boolean useDependencyVersion = true;
            final CharArraySet stopWords = SearchFieldAnalyzer.getStopWords();
            if (dependency.getName() != null && !dependency.getName().isEmpty()) {
                final String name = dependency.getName();
                for (String word : product.split("[^a-zA-Z0-9]")) {
                    useDependencyVersion &= name.contains(word) || stopWords.contains(word)
                            || wordMatchesEcosystem(dependency.getEcosystem(), word);
                }
            }

            if (useDependencyVersion) {
                //TODO - we need to filter this so that we only use this if something in the
                //dependency.getName() matches the vendor/product in some way
                final DependencyVersion depVersion = new DependencyVersion(dependency.getVersion());
                if (depVersion.getVersionParts().size() > 0) {
                    cpeBuilder.part(Part.APPLICATION).vendor(vendor).product(product);
                    addVersionAndUpdate(depVersion, cpeBuilder);
                    try {
                        final Cpe depCpe = cpeBuilder.build();
                        final String url = CpeIdentifier.nvdSearchUrlFor(vendor, product, depCpe.getVersion());
                        final IdentifierMatch match = new IdentifierMatch(depCpe, url, IdentifierConfidence.EXACT_MATCH, confidence);
                        collected.add(match);
                    } catch (CpeValidationException ex) {
                        throw new AnalysisException(String.format("Unable to create a CPE for %s:%s:%s", vendor, product, depVersion));
                    }
                }
            }
        }
    }

    /**
     * If a CPE product word represents the ecosystem of a dependency it is not required
     * to appear in the dependencyName to still consider the CPE product a match.
     *
     * @param ecosystem The ecosystem of the dependency
     * @param word       The word from the CPE product to check
     * @return {@code true} when the CPE product word is known to match the ecosystem of the dependency
     * @implNote This method is not intended to cover every possible case where the ecosystem is represented by the word. It is a
     * best-effort attempt to prevent {@link #considerDependencyVersion(Dependency, String, String, Confidence, Set)}
     * from not taking an exact-match versioned CPE into account because the ecosystem-related word does not appear in
     * the dependencyName. It helps prevent false-positive cases like https://github.com/dependency-check/DependencyCheck/issues/5545
     * @see #considerDependencyVersion(Dependency, String, String, Confidence, Set)
     */
    private boolean wordMatchesEcosystem(@Nullable String ecosystem, String word) {
        if (Ecosystem.JAVA.equalsIgnoreCase(word)) {
            return Ecosystem.JAVA.equals(ecosystem);
        }
        return false;
    }

    /**
     * <p>
     * Returns the setting key to determine if the analyzer is enabled.</p>
     *
     * @return the key for the analyzer's enabled property
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_CPE_ENABLED;
    }

    /**
     * Filters the given list of CPE Entries (plus ecosystem) for the given
     * dependencies ecosystem.
     *
     * @param ecosystem the dependencies ecosystem
     * @param entries the CPE Entries (plus ecosystem)
     * @return the filtered list of CPE entries
     */
    private Set<Cpe> filterEcosystem(String ecosystem, Set<CpePlus> entries) {
        if (entries == null || entries.isEmpty()) {
            return null;
        }
        if (ecosystem != null) {
            return entries.stream().filter(c
                    -> c.getEcosystem() == null
                    || c.getEcosystem().equals(ecosystem)
                    //some ios CVE/CPEs are listed under native
                    || (Ecosystem.IOS.equals(ecosystem) && Ecosystem.NATIVE.equals(c.getEcosystem())))
                    .map(CpePlus::getCpe)
                    .collect(Collectors.toSet());
        }
        return entries.stream()
                .map(CpePlus::getCpe)
                .collect(Collectors.toSet());
    }

    /**
     * Add the given version to the CpeBuilder - this method attempts to parse
     * out the update from the version and correctly set the value in the CPE.
     *
     * @param depVersion the version to add
     * @param cpeBuilder a reference to the CPE Builder
     */
    private void addVersionAndUpdate(DependencyVersion depVersion, final CpeBuilder cpeBuilder) {
        final int idx = depVersion.getVersionParts().size() - 1;
        if (idx > 0 && depVersion.getVersionParts().get(idx)
                .matches("^(v|final|release|snapshot|r|b|beta|a|alpha|u|rc|sp|dev|revision|service|build|pre|p|patch|update|m|20\\d\\d).*$")) {
            cpeBuilder.version(StringUtils.join(depVersion.getVersionParts().subList(0, idx), "."));
            //when written - no update versions in the NVD start with v### - they all strip the v off
            if (depVersion.getVersionParts().get(idx).matches("^v\\d.*$")) {
                cpeBuilder.update(depVersion.getVersionParts().get(idx).substring(1));
            } else {
                cpeBuilder.update(depVersion.getVersionParts().get(idx));
            }
        } else {
            cpeBuilder.version(depVersion.toString());
        }
    }

    /**
     * The confidence whether the identifier is an exact match, or a best guess.
     */
    private enum IdentifierConfidence {

        /**
         * An exact match for the CPE.
         */
        EXACT_MATCH,
        /**
         * A best guess for the CPE.
         */
        BEST_GUESS,
        /**
         * The entire vendor/product group must be added (without a guess at
         * version) because there is a CVE with a VS that only specifies
         * vendor/product.
         */
        BROAD_MATCH
    }

    /**
     * A simple object to hold an identifier and carry information about the
     * confidence in the identifier.
     */
    private static class IdentifierMatch implements Comparable<IdentifierMatch> {

        /**
         * The confidence whether this is an exact match, or a best guess.
         */
        private IdentifierConfidence identifierConfidence;
        /**
         * The CPE identifier.
         */
        private CpeIdentifier identifier;

        /**
         * Constructs an IdentifierMatch.
         *
         * @param cpe the CPE value for the match
         * @param url the URL of the identifier
         * @param identifierConfidence the confidence in the identifier: best
         * guess or exact match
         * @param evidenceConfidence the confidence of the evidence used to find
         * the identifier
         */
        IdentifierMatch(Cpe cpe, String url, IdentifierConfidence identifierConfidence, Confidence evidenceConfidence) {
            this.identifier = new CpeIdentifier(cpe, url, evidenceConfidence);
            this.identifierConfidence = identifierConfidence;
        }

        //<editor-fold defaultstate="collapsed" desc="Property implementations: evidenceConfidence, confidence, identifier">
        /**
         * Get the value of evidenceConfidence
         *
         * @return the value of evidenceConfidence
         */
        public Confidence getEvidenceConfidence() {
            return this.identifier.getConfidence();
        }

        /**
         * Set the value of evidenceConfidence
         *
         * @param evidenceConfidence new value of evidenceConfidence
         */
        public void setEvidenceConfidence(Confidence evidenceConfidence) {
            this.identifier.setConfidence(evidenceConfidence);
        }

        /**
         * Get the value of confidence.
         *
         * @return the value of confidence
         */
        public IdentifierConfidence getIdentifierConfidence() {
            return identifierConfidence;
        }

        /**
         * Set the value of confidence.
         *
         * @param confidence new value of confidence
         */
        public void setIdentifierConfidence(IdentifierConfidence confidence) {
            this.identifierConfidence = confidence;
        }

        /**
         * Get the value of identifier.
         *
         * @return the value of identifier
         */
        public CpeIdentifier getIdentifier() {
            return identifier;
        }

        /**
         * Set the value of identifier.
         *
         * @param identifier new value of identifier
         */
        public void setIdentifier(CpeIdentifier identifier) {
            this.identifier = identifier;
        }
        //</editor-fold>
        //<editor-fold defaultstate="collapsed" desc="Standard implementations of toString, hashCode, and equals">

        /**
         * Standard toString() implementation.
         *
         * @return the string representation of the object
         */
        @Override
        public String toString() {
            return "IdentifierMatch{ IdentifierConfidence=" + identifierConfidence + ", identifier=" + identifier + '}';
        }

        /**
         * Standard hashCode() implementation.
         *
         * @return the hashCode
         */
        @Override
        public int hashCode() {
            return new HashCodeBuilder(115, 303)
                    .append(identifierConfidence)
                    .append(identifier)
                    .toHashCode();
        }

        /**
         * Standard equals implementation.
         *
         * @param obj the object to compare
         * @return true if the objects are equal, otherwise false
         */
        @Override
        public boolean equals(Object obj) {
            if (obj == null || !(obj instanceof IdentifierMatch)) {
                return false;
            }
            if (this == obj) {
                return true;
            }
            final IdentifierMatch other = (IdentifierMatch) obj;
            return new EqualsBuilder()
                    .append(identifierConfidence, other.identifierConfidence)
                    .append(identifier, other.identifier)
                    .build();
        }
        //</editor-fold>

        /**
         * Standard implementation of compareTo that compares identifier
         * confidence, evidence confidence, and then the identifier.
         *
         * @param o the IdentifierMatch to compare to
         * @return the natural ordering of IdentifierMatch
         */
        @Override
        public int compareTo(@NonNull IdentifierMatch o) {
            return new CompareToBuilder()
                    .append(identifierConfidence, o.identifierConfidence)
                    .append(identifier, o.identifier)
                    .toComparison();
        }
    }

    /**
     * Command line tool for querying the Lucene CPE Index.
     *
     * @param args not used
     */
    @SuppressWarnings("InfiniteLoopStatement")
    public static void main(String[] args) {
        final Settings props = new Settings();
        try (Engine en = new Engine(Engine.Mode.EVIDENCE_PROCESSING, props)) {
            en.openDatabase(false, false);
            final CPEAnalyzer analyzer = new CPEAnalyzer();
            analyzer.initialize(props);
            analyzer.prepareAnalyzer(en);
            LOGGER.error("test");
            System.out.println("Memory index query for ODC");
            try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
                while (true) {

                    final Map<String, MutableInt> vendor = new HashMap<>();
                    final Map<String, MutableInt> product = new HashMap<>();
                    System.out.print("Vendor: ");
                    String[] parts = br.readLine().split(" ");
                    for (String term : parts) {
                        final MutableInt count = vendor.get(term);
                        if (count == null) {
                            vendor.put(term, new MutableInt(0));
                        } else {
                            count.add(1);
                        }
                    }
                    System.out.print("Product: ");
                    parts = br.readLine().split(" ");
                    for (String term : parts) {
                        final MutableInt count = product.get(term);
                        if (count == null) {
                            product.put(term, new MutableInt(0));
                        } else {
                            count.add(1);
                        }
                    }
                    final List<IndexEntry> list = analyzer.searchCPE(vendor, product, new HashSet<>(), new HashSet<>(), "default");
                    if (list == null || list.isEmpty()) {
                        System.out.println("No results found");
                    } else {
                        list.forEach((e) -> System.out.printf("%s:%s (%f)%n", e.getVendor(), e.getProduct(),
                                e.getSearchScore()));
                    }
                    System.out.println();
                    System.out.println();
                }
            }
        } catch (InitializationException | IOException ex) {
            System.err.println("Lucene ODC search tool failed:");
            System.err.println(ex.getMessage());
        }
    }

    /**
     * Sets the reference to the CveDB.
     *
     * @param cveDb the CveDB
     */
    protected void setCveDB(CveDB cveDb) {
        this.cve = cveDb;
    }

    /**
     * returns a reference to the CveDB.
     *
     * @return a reference to the CveDB
     */
    protected CveDB getCveDB() {
        return this.cve;
    }

    /**
     * Sets the MemoryIndex.
     *
     * @param idx the memory index
     */
    protected void setMemoryIndex(MemoryIndex idx) {
        cpe = idx;
    }

    /**
     * Returns the memory index.
     *
     * @return the memory index
     */
    protected MemoryIndex getMemoryIndex() {
        return cpe;
    }

    /**
     * Sets the CPE Suppression Analyzer.
     *
     * @param suppression the CPE Suppression Analyzer
     */
    protected void setCpeSuppressionAnalyzer(CpeSuppressionAnalyzer suppression) {
        this.suppression = suppression;
    }
}
