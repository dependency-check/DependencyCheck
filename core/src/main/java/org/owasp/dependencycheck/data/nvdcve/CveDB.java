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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;
//CSOFF: AvoidStarImport

import com.google.common.io.Resources;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import io.github.jeremylong.openvulnerability.client.nvd.Config;
import io.github.jeremylong.openvulnerability.client.nvd.CpeMatch;
import org.apache.commons.collections.map.ReferenceMap;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.JDBCType;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import java.util.stream.Collectors;
import org.anarres.jdiagnostics.DefaultQuery;

import static org.apache.commons.collections.map.AbstractReferenceMap.HARD;
import static org.apache.commons.collections.map.AbstractReferenceMap.SOFT;
import org.owasp.dependencycheck.analyzer.exception.LambdaExceptionWrapper;
import org.owasp.dependencycheck.analyzer.exception.UnexpectedAnalysisException;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import static org.owasp.dependencycheck.data.nvdcve.CveDB.PreparedStatementCveDb.*;
import org.owasp.dependencycheck.data.update.cpe.CpeEcosystemCache;
import org.owasp.dependencycheck.data.update.cpe.CpePlus;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV2Data;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3Data;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV4Data;
import io.github.jeremylong.openvulnerability.client.nvd.LangString;
import io.github.jeremylong.openvulnerability.client.nvd.Node;
import io.github.jeremylong.openvulnerability.client.nvd.Reference;
import io.github.jeremylong.openvulnerability.client.nvd.Weakness;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeBuilder;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.exceptions.CpeValidationException;

/**
 * The database holding information about the NVD CVE data. This class is safe
 * to be accessed from multiple threads in parallel, however internally only one
 * connection will be used.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class CveDB implements AutoCloseable {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CveDB.class);

    /**
     * Resource location for SQL file containing updates to the ecosystem cache.
     */
    public static final String DB_ECOSYSTEM_CACHE = "data/dbEcosystemCacheUpdates.sql";

    /**
     * The database connection manager.
     */
    private final DatabaseManager databaseManager;

    /**
     * The bundle of statements used when accessing the database.
     */
    private ResourceBundle statementBundle;
    /**
     * Database properties object containing the 'properties' from the database
     * table.
     */
    private DatabaseProperties databaseProperties;
    /**
     * The filter for 2.3 CPEs in the CVEs - we don't import unless we get a
     * match.
     */
    private final String cpeStartsWithFilter;
    /**
     * Cache for CVE lookup; used to speed up the vulnerability search process.
     */
    @SuppressWarnings("unchecked")
    private final Map<String, List<Vulnerability>> vulnerabilitiesForCpeCache = Collections.synchronizedMap(new ReferenceMap(HARD, SOFT));
    /**
     * The configured settings
     */
    private final Settings settings;

    /**
     * Utility to extract information from
     * {@linkplain org.owasp.dependencycheck.data.nvd.json.DefCveItem}.
     */
    private final CveItemOperator cveItemConverter;
    /**
     * Flag indicating if the database is Oracle.
     */
    private boolean isOracle = false;
    /**
     * Flag indicating if the database is H2.
     */
    private boolean isH2 = false;

    /**
     * Updates the EcoSystem Cache.
     *
     * @return The number of records updated by the DB_ECOSYSTEM_CACHE update
     * script.
     */
    public int updateEcosystemCache() {
        LOGGER.debug("Updating the ecosystem cache");
        int updateCount = 0;
        try {
            final URL url = Resources.getResource(DB_ECOSYSTEM_CACHE);
            final List<String> sql = Resources.readLines(url, StandardCharsets.UTF_8);

            try (Connection conn = databaseManager.getConnection(); Statement statement = conn.createStatement()) {
                for (String single : sql) {
                    updateCount += statement.executeUpdate(single);
                }
            } catch (SQLException ex) {
                LOGGER.debug("", ex);
                throw new DatabaseException("Unable to update the ecosystem cache", ex);
            }
        } catch (IOException ex) {
            throw new DatabaseException("Unable to update the ecosystem cache", ex);
        } catch (LinkageError ex) {
            LOGGER.debug(new DefaultQuery(ex).call().toString());
        }
        return updateCount;
    }

    /**
     * The enumeration value names must match the keys of the statements in the
     * statement bundles "dbStatements*.properties".
     */
    enum PreparedStatementCveDb {
        /**
         * Key for SQL Statement.
         */
        CLEANUP_ORPHANS,
        /**
         * Key for update ecosystem.
         */
        UPDATE_ECOSYSTEM,
        /**
         * Key for update ecosystem.
         */
        UPDATE_ECOSYSTEM2,
        /**
         * Key for SQL Statement.
         */
        COUNT_CPE,
        /**
         * Key for SQL Statement.
         */
        DELETE_VULNERABILITY,
        /**
         * Key for SQL Statement.
         */
        INSERT_PROPERTY,
        /**
         * Key for SQL Statement.
         */
        INSERT_CWE,
        /**
         * Key for SQL Statement.
         */
        INSERT_REFERENCE,
        /**
         * Key for SQL Statement.
         */
        INSERT_SOFTWARE,
        /**
         * Key for SQL Statement.
         */
        MERGE_PROPERTY,
        /**
         * Key for SQL Statement.
         */
        SELECT_CPE_ENTRIES,
        /**
         * Key for SQL Statement.
         */
        SELECT_CVE_FROM_SOFTWARE,
        /**
         * Key for SQL Statement.
         */
        SELECT_PROPERTIES,
        /**
         * Key for SQL Statement.
         */
        SELECT_VULNERABILITY_CWE,
        /**
         * Key for SQL Statement.
         */
        SELECT_REFERENCES,
        /**
         * Key for SQL Statement.
         */
        SELECT_SOFTWARE,
        /**
         * Key for SQL Statement.
         */
        SELECT_VENDOR_PRODUCT_LIST,
        /**
         * Key for SQL Statement.
         */
        SELECT_VENDOR_PRODUCT_LIST_FOR_NODE,
        /**
         * Key for SQL Statement.
         */
        SELECT_VULNERABILITY,
        /**
         * Key for SQL Statement.
         */
        UPDATE_PROPERTY,
        /**
         * Key for SQL Statement.
         */
        UPDATE_VULNERABILITY,
        /**
         * Key for SQL Statement.
         */
        SELECT_CPE_ECOSYSTEM,
        /**
         * Key for SQL Statement.
         */
        MERGE_CPE_ECOSYSTEM,
        /**
         * Key for SQL Statement.
         */
        DELETE_UNUSED_DICT_CPE,
        /**
         * Key for SQL Statement.
         */
        ADD_DICT_CPE,
        /**
         * Key for SQL Statement.
         */
        SELECT_KNOWN_EXPLOITED_VULNERABILITIES,
        /**
         * Key for SQL Statement.
         */
        MERGE_KNOWN_EXPLOITED
    }

    /**
     * Creates a new CveDB object and opens the database connection. Note, the
     * connection must be closed by the caller by calling the close method.
     *
     * @param settings the configured settings
     * @throws DatabaseException thrown if there is an exception opening the
     * database.
     */
    public CveDB(Settings settings) throws DatabaseException {
        this.settings = settings;
        this.cpeStartsWithFilter = settings.getString(Settings.KEYS.CVE_CPE_STARTS_WITH_FILTER, "cpe:2.3:a:");
        this.cveItemConverter = new CveItemOperator(cpeStartsWithFilter);
        databaseManager = new DatabaseManager(settings);
        statementBundle = databaseManager.getSqlStatements();
        isOracle = databaseManager.isOracle();
        isH2 = databaseManager.isH2Connection();
    }

    /**
     * Opens the database connection pool.
     */
    public void open() {
        databaseManager.open();
        databaseProperties = new DatabaseProperties(this);
    }

    /**
     * Closes the database connection. Close should be called on this object
     * when it is done being used.
     */
    @Override
    public void close() {
        if (isOpen()) {
            LOGGER.debug("Closing database");
            clearCache();
            LOGGER.debug("Cache cleared");
            try {
                databaseManager.close();
                LOGGER.debug("Connection closed");
            } catch (Throwable ex) {
                LOGGER.error("There was an exception attempting to close the CveDB, see the log for more details.");
                LOGGER.debug("", ex);
            }
            releaseResources();
            LOGGER.debug("Resources released");
            databaseManager.cleanup();
        }
    }

    /**
     * Releases the resources used by CveDB.
     */
    private void releaseResources() {
        statementBundle = null;
        databaseProperties = null;
    }

    /**
     * Returns whether the database connection is open or closed.
     *
     * @return whether the database connection is open or closed
     */
    public boolean isOpen() {
        return databaseManager.isOpen();
    }

    /**
     * Creates a prepared statement from the given key. The SQL is stored in a
     * properties file and the key is used to lookup the specific query.
     *
     * @param connection the database connection
     * @param key the key to select the prepared statement from the properties
     * file
     * @param parameter the first parameter to pass into the statement
     * @return the prepared statement
     * @throws DatabaseException throw if there is an error generating the
     * prepared statement
     */
    private PreparedStatement getPreparedStatement(Connection connection, PreparedStatementCveDb key, String parameter)
            throws DatabaseException, SQLException {
        final PreparedStatement preparedStatement = getPreparedStatement(connection, key);
        preparedStatement.setString(1, parameter);
        return preparedStatement;
    }

    /**
     * Creates a prepared statement from the given key. The SQL is stored in a
     * properties file and the key is used to lookup the specific query.
     *
     * @param connection the database connection
     * @param key the key to select the prepared statement from the properties
     * file
     * @param parameter the first parameter to pass into the statement
     * @return the prepared statement
     * @throws DatabaseException throw if there is an error generating the
     * prepared statement
     */
    private PreparedStatement getPreparedStatement(Connection connection, PreparedStatementCveDb key, int parameter)
            throws DatabaseException, SQLException {
        final PreparedStatement preparedStatement = getPreparedStatement(connection, key);
        preparedStatement.setInt(1, parameter);
        return preparedStatement;
    }

    /**
     * Creates a prepared statement from the given key. The SQL is stored in a
     * properties file and the key is used to lookup the specific query.
     *
     * @param connection the database connection
     * @param key the key to select the prepared statement from the properties
     * file
     * @return the prepared statement
     * @throws DatabaseException throw if there is an error generating the
     * prepared statement
     */
    private PreparedStatement getPreparedStatement(Connection connection, PreparedStatementCveDb key) throws DatabaseException {
        PreparedStatement preparedStatement = null;
        try {
            final String statementString = statementBundle.getString(key.name());
            if (isOracle && key == UPDATE_VULNERABILITY) {
                preparedStatement = connection.prepareCall(statementString);
//            } else if (key == INSERT_CPE) {
//                final String[] returnedColumns = {"id"};
//                preparedStatement = connection.prepareStatement(statementString, returnedColumns);
            } else {
                preparedStatement = connection.prepareStatement(statementString);
            }
            if (isOracle) {
                // Oracle has a default fetch-size of 10; MariaDB, MySQL, SQLServer and PostgreSQL by default cache the full
                // resultset at the client https://venkatsadasivam.com/2009/02/01/jdbc-performance-tuning-with-optimal-fetch-size/
                preparedStatement.setFetchSize(10_000);
            }
        } catch (SQLException ex) {
            throw new DatabaseException(ex);
        } catch (MissingResourceException ex) {
            if (!ex.getMessage().contains("key MERGE_PROPERTY")) {
                throw new DatabaseException(ex);
            }
        }
        return preparedStatement;
    }

    /**
     * Cleans up the object and ensures that "close" has been called.
     *
     * @throws Throwable thrown if there is a problem
     */
    @Override
    @SuppressWarnings("FinalizeDeclaration")
    protected void finalize() throws Throwable {
        LOGGER.debug("Entering finalize");
        close();
        super.finalize();
    }

    /**
     * Get the value of databaseProperties.
     *
     * @return the value of databaseProperties
     */
    public DatabaseProperties getDatabaseProperties() {
        return databaseProperties;
    }

    /**
     * Used within the unit tests to reload the database properties.
     *
     * @return the database properties
     */
    DatabaseProperties reloadProperties() {
        databaseProperties = new DatabaseProperties(this);
        return databaseProperties;
    }

    /**
     * Searches the CPE entries in the database and retrieves all entries for a
     * given vendor and product combination. The returned list will include all
     * versions of the product that are registered in the NVD CVE data.
     *
     * @param vendor the identified vendor name of the dependency being analyzed
     * @param product the identified name of the product of the dependency being
     * analyzed
     * @return a set of vulnerable software
     */
    public Set<CpePlus> getCPEs(String vendor, String product) {
        final Set<CpePlus> cpe = new HashSet<>();
        try (Connection conn = databaseManager.getConnection(); PreparedStatement ps = getPreparedStatement(conn, SELECT_CPE_ENTRIES)) {
            //part, vendor, product, version, update_version, edition,
            //lang, sw_edition, target_sw, target_hw, other, ecosystem
            ps.setString(1, vendor);
            ps.setString(2, product);
            try (ResultSet rs = ps.executeQuery()) {
                final CpeBuilder builder = new CpeBuilder();
                while (rs.next()) {
                    final Cpe entry = builder
                            .part(rs.getString(1))
                            .vendor(rs.getString(2))
                            .product(rs.getString(3))
                            .version(rs.getString(4))
                            .update(rs.getString(5))
                            .edition(rs.getString(6))
                            .language(rs.getString(7))
                            .swEdition(rs.getString(8))
                            .targetSw(rs.getString(9))
                            .targetHw(rs.getString(10))
                            .other(rs.getString(11)).build();
                    final CpePlus plus = new CpePlus(entry, rs.getString(12));
                    cpe.add(plus);
                }
            }
        } catch (SQLException | CpeParsingException | CpeValidationException ex) {
            LOGGER.error("An unexpected SQL Exception occurred; please see the verbose log for more details.");
            LOGGER.debug("", ex);
        }
        return cpe;
    }

    /**
     * Returns the entire list of vendor/product combinations.
     *
     * @return the entire list of vendor/product combinations
     * @throws DatabaseException thrown when there is an error retrieving the
     * data from the DB
     */
    public Set<Pair<String, String>> getVendorProductList() throws DatabaseException {
        final Set<Pair<String, String>> data = new HashSet<>();
        try (Connection conn = databaseManager.getConnection();
                PreparedStatement ps = getPreparedStatement(conn, SELECT_VENDOR_PRODUCT_LIST);
                ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                data.add(new Pair<>(rs.getString(1), rs.getString(2)));
            }
        } catch (SQLException ex) {
            final String msg = "An unexpected SQL Exception occurred; please see the verbose log for more details.";
            throw new DatabaseException(msg, ex);
        }
        return data;
    }

    /**
     * Returns the entire list of vendor/product combinations filtered for just
     * Node JS related products.
     *
     * @return the list of vendor/product combinations that are known to be
     * related to Node JS
     * @throws DatabaseException thrown when there is an error retrieving the
     * data from the DB
     */
    public Set<Pair<String, String>> getVendorProductListForNode() throws DatabaseException {
        final Set<Pair<String, String>> data = new HashSet<>();
        try (Connection conn = databaseManager.getConnection();
                PreparedStatement ps = getPreparedStatement(conn, SELECT_VENDOR_PRODUCT_LIST_FOR_NODE);
                ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                data.add(new Pair<>(rs.getString(1), rs.getString(2)));
            }
        } catch (SQLException ex) {
            final String msg = "An unexpected SQL Exception occurred; please see the verbose log for more details.";
            throw new DatabaseException(msg, ex);
        }
        return data;
    }

    /**
     * Returns a set of properties.
     *
     * @return the properties from the database
     */
    public Properties getProperties() {
        final Properties prop = new Properties();
        try (Connection conn = databaseManager.getConnection();
                PreparedStatement ps = getPreparedStatement(conn, SELECT_PROPERTIES);
                ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                prop.setProperty(rs.getString(1), rs.getString(2));
            }
        } catch (SQLException ex) {
            LOGGER.error("An unexpected SQL Exception occurred; please see the verbose log for more details.");
            LOGGER.debug("", ex);
        }
        return prop;
    }

    /**
     * Saves a property to the database.
     *
     * @param key the property key
     * @param value the property value
     */
    public void saveProperty(String key, String value) {
        clearCache();
        try (Connection conn = databaseManager.getConnection(); PreparedStatement mergeProperty = getPreparedStatement(conn, MERGE_PROPERTY)) {
            if (mergeProperty != null) {
                mergeProperty.setString(1, key);
                mergeProperty.setString(2, value);
                mergeProperty.execute();
            } else {
                // No Merge statement, so doing an Update/Insert...
                try (PreparedStatement updateProperty = getPreparedStatement(conn, UPDATE_PROPERTY)) {
                    updateProperty.setString(1, value);
                    updateProperty.setString(2, key);
                    if (updateProperty.executeUpdate() == 0) {
                        try (PreparedStatement insertProperty = getPreparedStatement(conn, INSERT_PROPERTY)) {
                            insertProperty.setString(1, key);
                            insertProperty.setString(2, value);
                            insertProperty.executeUpdate();
                        }
                    }
                }
            }
        } catch (SQLException ex) {
            LOGGER.warn("Unable to save property '{}' with a value of '{}' to the database", key, value);
            LOGGER.debug("", ex);
        }
    }

    /**
     * Clears cache. Should be called whenever something is modified. While this
     * is not the optimal cache eviction strategy, this is good enough for
     * typical usage (update DB and then only read) and it is easier to maintain
     * the code.
     * <p>
     * It should be also called when DB is closed.
     * </p>
     */
    private void clearCache() {
        vulnerabilitiesForCpeCache.clear();
    }

    /**
     * Retrieves the vulnerabilities associated with the specified CPE.
     *
     * @param cpe the CPE to retrieve vulnerabilities for
     * @return a list of Vulnerabilities
     * @throws DatabaseException thrown if there is an exception retrieving data
     */
    public List<Vulnerability> getVulnerabilities(Cpe cpe) throws DatabaseException {
        final List<Vulnerability> cachedVulnerabilities = vulnerabilitiesForCpeCache.get(cpe.toCpe23FS());
        if (cachedVulnerabilities != null) {
            LOGGER.debug("Cache hit for {}", cpe.toCpe23FS());
            return cachedVulnerabilities;
        } else {
            LOGGER.debug("Cache miss for {}", cpe.toCpe23FS());
        }

        final List<Vulnerability> vulnerabilities = new ArrayList<>();
        try (Connection conn = databaseManager.getConnection(); PreparedStatement ps = getPreparedStatement(conn, SELECT_CVE_FROM_SOFTWARE)) {
            ps.setString(1, cpe.getVendor());
            ps.setString(2, cpe.getProduct());
            try (ResultSet rs = ps.executeQuery()) {
                String currentCVE = "";
                final Set<VulnerableSoftware> vulnSoftware = new HashSet<>();
                final VulnerableSoftwareBuilder vulnerableSoftwareBuilder = new VulnerableSoftwareBuilder();
                while (rs.next()) {
                    final String cveId = rs.getString(1);
                    if (currentCVE.isEmpty()) {
                        //first loop we don't have the cveId
                        currentCVE = cveId;
                    }
                    if (!vulnSoftware.isEmpty() && !currentCVE.equals(cveId)) { //check for match and add
                        final VulnerableSoftware matchedCPE = getMatchingSoftware(cpe, vulnSoftware);
                        if (matchedCPE != null) {
                            final Vulnerability v = getVulnerability(currentCVE, conn);
                            if (v != null) {
                                v.setMatchedVulnerableSoftware(matchedCPE);
                                v.setSource(Vulnerability.Source.NVD);
                                vulnerabilities.add(v);
                            }
                        }
                        vulnSoftware.clear();
                        currentCVE = cveId;
                    }
                    // 1 cve, 2 part, 3 vendor, 4 product, 5 version, 6 update_version, 7 edition,
                    // 8 lang, 9 sw_edition, 10 target_sw, 11 target_hw, 12 other, 13 versionEndExcluding,
                    //14 versionEndIncluding, 15 versionStartExcluding, 16 versionStartIncluding, 17 vulnerable
                    final VulnerableSoftware vs;
                    try {
                        vs = vulnerableSoftwareBuilder.part(rs.getString(2)).vendor(rs.getString(3))
                                .product(rs.getString(4)).version(rs.getString(5)).update(rs.getString(6))
                                .edition(rs.getString(7)).language(rs.getString(8)).swEdition(rs.getString(9))
                                .targetSw(rs.getString(10)).targetHw(rs.getString(11)).other(rs.getString(12))
                                .versionEndExcluding(rs.getString(13)).versionEndIncluding(rs.getString(14))
                                .versionStartExcluding(rs.getString(15)).versionStartIncluding(rs.getString(16))
                                .vulnerable(rs.getBoolean(17)).build();
                    } catch (CpeParsingException | CpeValidationException ex) {
                        throw new DatabaseException("Database contains an invalid Vulnerable Software Entry", ex);
                    }
                    vulnSoftware.add(vs);
                }

                //remember to process the last set of CVE/CPE entries
                final VulnerableSoftware matchedCPE = getMatchingSoftware(cpe, vulnSoftware);
                if (matchedCPE != null) {
                    final Vulnerability v = getVulnerability(currentCVE, conn);
                    if (v != null) {
                        v.setMatchedVulnerableSoftware(matchedCPE);
                        v.setSource(Vulnerability.Source.NVD);
                        vulnerabilities.add(v);
                    }
                }
            }
        } catch (SQLException ex) {
            throw new DatabaseException("Exception retrieving vulnerability for " + cpe.toCpe23FS(), ex);
        }
        vulnerabilitiesForCpeCache.put(cpe.toCpe23FS(), vulnerabilities);
        return vulnerabilities;
    }

    /**
     * Gets a vulnerability for the provided CVE.
     *
     * @param cve the CVE to lookup
     * @return a vulnerability object
     * @throws DatabaseException if an exception occurs
     */
    public Vulnerability getVulnerability(String cve) throws DatabaseException {
        try (Connection conn = databaseManager.getConnection()) {
            return getVulnerability(cve, conn);
        } catch (SQLException ex) {
            throw new DatabaseException("Error retrieving " + cve, ex);
        }
    }

    /**
     * Gets a vulnerability for the provided CVE.
     *
     * @param cve the CVE to lookup
     * @param conn already active database connection
     * @return a vulnerability object
     * @throws DatabaseException if an exception occurs
     */
    public Vulnerability getVulnerability(String cve, Connection conn) throws DatabaseException {
        final int cveId;
        final VulnerableSoftwareBuilder vulnerableSoftwareBuilder = new VulnerableSoftwareBuilder();
        Vulnerability vuln = null;
        try {
            try (PreparedStatement psV = getPreparedStatement(conn, SELECT_VULNERABILITY, cve); ResultSet rsV = psV.executeQuery()) {
                if (rsV.next()) {
                    //1.id, 2.description,
                    cveId = rsV.getInt(1);
                    vuln = new Vulnerability();
                    vuln.setSource(Vulnerability.Source.NVD);
                    vuln.setName(cve);
                    vuln.setDescription(rsV.getString(2));

                    //3.v2Severity, 4.v2ExploitabilityScore, 5.v2ImpactScore, 6.v2AcInsufInfo, 7.v2ObtainAllPrivilege,
                    //8.v2ObtainUserPrivilege, 9.v2ObtainOtherPrivilege, 10.v2UserInteractionRequired, 11.v2Score,
                    //12.v2AccessVector, 13.v2AccessComplexity, 14.v2Authentication, 15.v2ConfidentialityImpact,
                    //16.v2IntegrityImpact, 17.v2AvailabilityImpact, 18.v2Version,
                    if (rsV.getObject(11) != null) {

                        final CvssV2Data.AccessVectorType accessVector = CvssV2Data.AccessVectorType.fromValue(rsV.getString(12));
                        final CvssV2Data.AccessComplexityType accessComplexity = CvssV2Data.AccessComplexityType.fromValue(rsV.getString(13));
                        final CvssV2Data.AuthenticationType authentication = CvssV2Data.AuthenticationType.fromValue(rsV.getString(14));
                        final CvssV2Data.CiaType confidentialityImpact = CvssV2Data.CiaType.fromValue(rsV.getString(15));
                        final CvssV2Data.CiaType integrityImpact = CvssV2Data.CiaType.fromValue(rsV.getString(16));
                        final CvssV2Data.CiaType availabilityImpact = CvssV2Data.CiaType.fromValue(rsV.getString(17));
                        final String vector = String.format("/AV:%s/AC:%s/Au:%s/C:%s/I:%s/A:%s",
                                accessVector == null ? "" : accessVector.value().substring(0, 1),
                                accessComplexity == null ? "" : accessComplexity.value().substring(0, 1),
                                authentication == null ? "" : authentication.value().substring(0, 1),
                                confidentialityImpact == null ? "" : confidentialityImpact.value().substring(0, 1),
                                integrityImpact == null ? "" : integrityImpact.value().substring(0, 1),
                                availabilityImpact == null ? "" : availabilityImpact.value().substring(0, 1));

                        //some older test data may not correctly have the version set.
                        String cveVersion = "2.0";
                        if (rsV.getString(18) != null) {
                            cveVersion = rsV.getString(18);
                        }
                        final CvssV2Data cvssData = new CvssV2Data(cveVersion, vector, accessVector,
                                accessComplexity, authentication, confidentialityImpact,
                                integrityImpact, availabilityImpact, rsV.getDouble(11), rsV.getString(3),
                                null, null, null, null, null, null, null, null, null, null);
                        final CvssV2 cvss = new CvssV2(null, CvssV2.Type.PRIMARY, cvssData, rsV.getString(3),
                                rsV.getDouble(4), rsV.getDouble(5), rsV.getBoolean(6), rsV.getBoolean(7),
                                rsV.getBoolean(8), rsV.getBoolean(9), rsV.getBoolean(10));
                        vuln.setCvssV2(cvss);
                    }
                    //19.v3ExploitabilityScore, 20.v3ImpactScore, 21.v3AttackVector, 22.v3AttackComplexity, 23.v3PrivilegesRequired,
                    //24.v3UserInteraction, 25.v3Scope, 26.v3ConfidentialityImpact, 27.v3IntegrityImpact, 28.v3AvailabilityImpact,
                    //29.v3BaseScore, 30.v3BaseSeverity, 31.v3Version
                    if (rsV.getObject(21) != null) {
                        //some older test data may not correctly have the version set.
                        String cveVersion = "3.1";
                        if (rsV.getString(31) != null) {
                            cveVersion = rsV.getString(31);
                        }
                        final CvssV3Data.Version version = CvssV3Data.Version.fromValue(cveVersion);
                        final CvssV3Data.AttackVectorType attackVector = CvssV3Data.AttackVectorType.fromValue(rsV.getString(21));
                        final CvssV3Data.AttackComplexityType attackComplexity = CvssV3Data.AttackComplexityType.fromValue(rsV.getString(22));
                        final CvssV3Data.PrivilegesRequiredType privilegesRequired = CvssV3Data.PrivilegesRequiredType.fromValue(rsV.getString(23));
                        final CvssV3Data.UserInteractionType userInteraction = CvssV3Data.UserInteractionType.fromValue(rsV.getString(24));
                        final CvssV3Data.ScopeType scope = CvssV3Data.ScopeType.fromValue(rsV.getString(25));
                        final CvssV3Data.CiaType confidentialityImpact = CvssV3Data.CiaType.fromValue(rsV.getString(26));
                        final CvssV3Data.CiaType integrityImpact = CvssV3Data.CiaType.fromValue(rsV.getString(27));
                        final CvssV3Data.CiaType availabilityImpact = CvssV3Data.CiaType.fromValue(rsV.getString(28));
                        final CvssV3Data.SeverityType baseSeverity = CvssV3Data.SeverityType.fromValue(rsV.getString(30));
                        final String vector = String.format("CVSS:%s/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
                                version == null ? "" : version,
                                attackVector == null ? "" : attackVector.value().substring(0, 1),
                                attackComplexity == null ? "" : attackComplexity.value().substring(0, 1),
                                privilegesRequired == null ? "" : privilegesRequired.value().substring(0, 1),
                                userInteraction == null ? "" : userInteraction.value().substring(0, 1),
                                scope == null ? "" : scope.value().substring(0, 1),
                                confidentialityImpact == null ? "" : confidentialityImpact.value().substring(0, 1),
                                integrityImpact == null ? "" : integrityImpact.value().substring(0, 1),
                                availabilityImpact == null ? "" : availabilityImpact.value().substring(0, 1));

                        final CvssV3Data cvssData = new CvssV3Data(version, vector, attackVector, attackComplexity, privilegesRequired,
                                userInteraction, scope, confidentialityImpact, integrityImpact, availabilityImpact,
                                rsV.getDouble(29), baseSeverity, CvssV3Data.ExploitCodeMaturityType.PROOF_OF_CONCEPT,
                                CvssV3Data.RemediationLevelType.NOT_DEFINED, CvssV3Data.ConfidenceType.REASONABLE, 0.0,
                                CvssV3Data.SeverityType.MEDIUM, CvssV3Data.CiaRequirementType.NOT_DEFINED,
                                CvssV3Data.CiaRequirementType.NOT_DEFINED, CvssV3Data.CiaRequirementType.NOT_DEFINED,
                                CvssV3Data.ModifiedAttackVectorType.ADJACENT_NETWORK, CvssV3Data.ModifiedAttackComplexityType.NOT_DEFINED,
                                CvssV3Data.ModifiedPrivilegesRequiredType.NOT_DEFINED, CvssV3Data.ModifiedUserInteractionType.NOT_DEFINED,
                                CvssV3Data.ModifiedScopeType.NOT_DEFINED, CvssV3Data.ModifiedCiaType.NOT_DEFINED,
                                CvssV3Data.ModifiedCiaType.NOT_DEFINED, CvssV3Data.ModifiedCiaType.NOT_DEFINED, 1.0,
                                CvssV3Data.SeverityType.NONE);
                        final CvssV3 cvss = new CvssV3(null, null, cvssData, rsV.getDouble(19), rsV.getDouble(20));
                        vuln.setCvssV3(cvss);
                    }
//                    32.v4version, 33.v4attackVector, 34.v4attackComplexity, 35.v4attackRequirements, 36.v4privilegesRequired, 
//                    37.v4userInteraction, 38.v4vulnConfidentialityImpact, 39.v4vulnIntegrityImpact, 40.v4vulnAvailabilityImpact, 
//                    41.v4subConfidentialityImpact, 42.v4subIntegrityImpact, 43.v4subAvailabilityImpact, 44.v4exploitMaturity, 
//                    45.v4confidentialityRequirement, 46.v4integrityRequirement, 47.v4availabilityRequirement, 48.v4modifiedAttackVector, 
//                    49.v4modifiedAttackComplexity, 50.v4modifiedAttackRequirements, 51.v4modifiedPrivilegesRequired, 52.v4modifiedUserInteraction, 
//                    53.v4modifiedVulnConfidentialityImpact, 54.v4modifiedVulnIntegrityImpact, 55.v4modifiedVulnAvailabilityImpact, 
//                    56.v4modifiedSubConfidentialityImpact, 57.v4modifiedSubIntegrityImpact, 58.v4modifiedSubAvailabilityImpact, 
//                    59.v4safety, 60.v4automatable, 61.v4recovery, 62.v4valueDensity, 63.v4vulnerabilityResponseEffort, 64.v4providerUrgency, 
//                    65.v4baseScore, 66.v4baseSeverity, 67.v4threatScore, 68.v4threatSeverity, 69.v4environmentalScore, 70.v4environmentalSeverity
//                    71.v4source, 72.v4type
                    if (rsV.getObject(33) != null) {
                        String vectorString = null;
                        
                        String value = rsV.getString(32);
                        CvssV4Data.Version version = CvssV4Data.Version.fromValue(value);                        
                        CvssV4Data.AttackVectorType attackVector = null;
                        value = rsV.getString(33);
                        if (value != null) {
                            attackVector = CvssV4Data.AttackVectorType.fromValue(value);
                        }
                        CvssV4Data.AttackComplexityType attackComplexity = null;
                        value = rsV.getString(34);
                        if (value != null) {
                            attackComplexity = CvssV4Data.AttackComplexityType.fromValue(value);
                        }
                        CvssV4Data.AttackRequirementsType attackRequirements = null;
                        value = rsV.getString(35);
                        if (value != null) {
                            attackRequirements = CvssV4Data.AttackRequirementsType.fromValue(value);
                        }
                        CvssV4Data.PrivilegesRequiredType privilegesRequired = null;
                        value = rsV.getString(36);
                        if (value != null) {
                            privilegesRequired = CvssV4Data.PrivilegesRequiredType.fromValue(value);
                        }
                        CvssV4Data.UserInteractionType userInteraction = null;
                        value = rsV.getString(37);
                        if (value != null) {
                            userInteraction = CvssV4Data.UserInteractionType.fromValue(value);
                        }
                        CvssV4Data.CiaType vulnConfidentialityImpact = null;
                        value = rsV.getString(38);
                        if (value != null) {
                            vulnConfidentialityImpact = CvssV4Data.CiaType.fromValue(value);
                        }
                        CvssV4Data.CiaType vulnIntegrityImpact = null;
                        value = rsV.getString(39);
                        if (value != null) {
                            vulnIntegrityImpact = CvssV4Data.CiaType.fromValue(value);
                        }
                        CvssV4Data.CiaType vulnAvailabilityImpact = null;
                        value = rsV.getString(40);
                        if (value != null) {
                            vulnAvailabilityImpact = CvssV4Data.CiaType.fromValue(value);
                        }
                        CvssV4Data.CiaType subConfidentialityImpact = null;
                        value = rsV.getString(41);
                        if (value != null) {
                            subConfidentialityImpact = CvssV4Data.CiaType.fromValue(value);
                        }
                        CvssV4Data.CiaType subIntegrityImpact = null;
                        value = rsV.getString(42);
                        if (value != null) {
                            subIntegrityImpact = CvssV4Data.CiaType.fromValue(value);
                        }
                        CvssV4Data.CiaType subAvailabilityImpact = null;
                        value = rsV.getString(43);
                        if (value != null) {
                            subAvailabilityImpact = CvssV4Data.CiaType.fromValue(value);
                        }
                        CvssV4Data.ExploitMaturityType exploitMaturity = null;
                        value = rsV.getString(44);
                        if (value != null) {
                            exploitMaturity = CvssV4Data.ExploitMaturityType.fromValue(value);
                        }
                        CvssV4Data.CiaRequirementType confidentialityRequirement = null;
                        value = rsV.getString(45);
                        if (value != null) {
                            confidentialityRequirement = CvssV4Data.CiaRequirementType.fromValue(value);
                        }
                        CvssV4Data.CiaRequirementType integrityRequirement = null;
                        value = rsV.getString(46);
                        if (value != null) {
                            integrityRequirement = CvssV4Data.CiaRequirementType.fromValue(value);
                        }
                        CvssV4Data.CiaRequirementType availabilityRequirement = null;
                        value = rsV.getString(47);
                        if (value != null) {
                            availabilityRequirement = CvssV4Data.CiaRequirementType.fromValue(value);
                        }
                        CvssV4Data.ModifiedAttackVectorType modifiedAttackVector = null;
                        value = rsV.getString(48);
                        if (value != null) {
                            modifiedAttackVector = CvssV4Data.ModifiedAttackVectorType.fromValue(value);
                        }
                        CvssV4Data.ModifiedAttackComplexityType modifiedAttackComplexity = null;
                        value = rsV.getString(49);
                        if (value != null) {
                            modifiedAttackComplexity = CvssV4Data.ModifiedAttackComplexityType.fromValue(value);
                        }
                        CvssV4Data.ModifiedAttackRequirementsType modifiedAttackRequirements = null;
                        value = rsV.getString(50);
                        if (value != null) {
                            modifiedAttackRequirements = CvssV4Data.ModifiedAttackRequirementsType.fromValue(value);
                        }
                        CvssV4Data.ModifiedPrivilegesRequiredType modifiedPrivilegesRequired = null;
                        value = rsV.getString(51);
                        if (value != null) {
                            modifiedPrivilegesRequired = CvssV4Data.ModifiedPrivilegesRequiredType.fromValue(value);
                        }
                        CvssV4Data.ModifiedUserInteractionType modifiedUserInteraction = null;
                        value = rsV.getString(52);
                        if (value != null) {
                            modifiedUserInteraction = CvssV4Data.ModifiedUserInteractionType.fromValue(value);
                        }
                        CvssV4Data.ModifiedCiaType modifiedVulnConfidentialityImpact = null;
                        value = rsV.getString(53);
                        if (value != null) {
                            modifiedVulnConfidentialityImpact = CvssV4Data.ModifiedCiaType.fromValue(value);
                        }
                        CvssV4Data.ModifiedCiaType modifiedVulnIntegrityImpact = null;
                        value = rsV.getString(54);
                        if (value != null) {
                            modifiedVulnIntegrityImpact = CvssV4Data.ModifiedCiaType.fromValue(value);
                        }
                        CvssV4Data.ModifiedCiaType modifiedVulnAvailabilityImpact = null;
                        value = rsV.getString(55);
                        if (value != null) {
                            modifiedVulnAvailabilityImpact = CvssV4Data.ModifiedCiaType.fromValue(value);
                        }
                        CvssV4Data.ModifiedCiaType modifiedSubConfidentialityImpact = null;
                        value = rsV.getString(56);
                        if (value != null) {
                            modifiedSubConfidentialityImpact = CvssV4Data.ModifiedCiaType.fromValue(value);
                        }
                        CvssV4Data.ModifiedCiaType modifiedSubIntegrityImpact = null;
                        value = rsV.getString(57);
                        if (value != null) {
                            modifiedSubIntegrityImpact = CvssV4Data.ModifiedCiaType.fromValue(value);
                        }
                        CvssV4Data.ModifiedCiaType modifiedSubAvailabilityImpact = null;
                        value = rsV.getString(58);
                        if (value != null) {
                            modifiedSubAvailabilityImpact = CvssV4Data.ModifiedCiaType.fromValue(value);
                        }
                        CvssV4Data.SafetyType safety = null;
                        value = rsV.getString(59);
                        if (value != null) {
                            safety = CvssV4Data.SafetyType.fromValue(value);
                        }
                        CvssV4Data.AutomatableType automatable = null;
                        value = rsV.getString(60);
                        if (value != null) {
                            automatable = CvssV4Data.AutomatableType.fromValue(value);
                        }
                        CvssV4Data.RecoveryType recovery = null;
                        value = rsV.getString(61);
                        if (value != null) {
                            recovery = CvssV4Data.RecoveryType.fromValue(value);
                        }
                        CvssV4Data.ValueDensityType valueDensity = null;
                        value = rsV.getString(62);
                        if (value != null) {
                            valueDensity = CvssV4Data.ValueDensityType.fromValue(value);
                        }
                        CvssV4Data.VulnerabilityResponseEffortType vulnerabilityResponseEffort = null;
                        value = rsV.getString(63);
                        if (value != null) {
                            vulnerabilityResponseEffort = CvssV4Data.VulnerabilityResponseEffortType.fromValue(value);
                        }
                        CvssV4Data.ProviderUrgencyType providerUrgency = null;
                        value = rsV.getString(64);
                        if (value != null) {
                            providerUrgency = CvssV4Data.ProviderUrgencyType.fromValue(value);
                        }
                        Double baseScore = null;
                        if (rsV.getObject(65) != null) {
                            baseScore = rsV.getDouble(65);
                        }
                        CvssV4Data.SeverityType baseSeverity = null;
                        value = rsV.getString(66);
                        if (value != null) {
                            baseSeverity = CvssV4Data.SeverityType.fromValue(value);
                        }
                        Double threatScore = null;
                        if (rsV.getObject(67) != null) {
                            threatScore = rsV.getDouble(67);
                        }
                        CvssV4Data.SeverityType threatSeverity = null;
                        value = rsV.getString(68);
                        if (value != null) {
                            threatSeverity = CvssV4Data.SeverityType.fromValue(value);
                        }
                        Double environmentalScore = null;
                        if (rsV.getObject(69) != null) {
                            environmentalScore = rsV.getDouble(69);
                        }
                        CvssV4Data.SeverityType environmentalSeverity = null;
                        value = rsV.getString(70);
                        if (value != null) {
                            environmentalSeverity = CvssV4Data.SeverityType.fromValue(value);
                        }
                        //initializing data twice to get the vector string. I really should have designed the object better...
                        CvssV4Data data = new CvssV4Data(version, vectorString, attackVector, attackComplexity, attackRequirements, privilegesRequired, 
                                userInteraction, vulnConfidentialityImpact, vulnIntegrityImpact, vulnAvailabilityImpact, subConfidentialityImpact, 
                                subIntegrityImpact, subAvailabilityImpact, exploitMaturity, confidentialityRequirement, integrityRequirement, 
                                availabilityRequirement, modifiedAttackVector, modifiedAttackComplexity, modifiedAttackRequirements, 
                                modifiedPrivilegesRequired, modifiedUserInteraction, modifiedVulnConfidentialityImpact, modifiedVulnIntegrityImpact, 
                                modifiedVulnAvailabilityImpact, modifiedSubConfidentialityImpact, modifiedSubIntegrityImpact, modifiedSubAvailabilityImpact, 
                                safety, automatable, recovery, valueDensity, vulnerabilityResponseEffort, providerUrgency, baseScore, baseSeverity, 
                                threatScore, threatSeverity, environmentalScore, environmentalSeverity);
                        vectorString = data.toString();
                        data = new CvssV4Data(version, vectorString, attackVector, attackComplexity, attackRequirements, privilegesRequired, 
                                userInteraction, vulnConfidentialityImpact, vulnIntegrityImpact, vulnAvailabilityImpact, subConfidentialityImpact, 
                                subIntegrityImpact, subAvailabilityImpact, exploitMaturity, confidentialityRequirement, integrityRequirement, 
                                availabilityRequirement, modifiedAttackVector, modifiedAttackComplexity, modifiedAttackRequirements, 
                                modifiedPrivilegesRequired, modifiedUserInteraction, modifiedVulnConfidentialityImpact, modifiedVulnIntegrityImpact, 
                                modifiedVulnAvailabilityImpact, modifiedSubConfidentialityImpact, modifiedSubIntegrityImpact, modifiedSubAvailabilityImpact, 
                                safety, automatable, recovery, valueDensity, vulnerabilityResponseEffort, providerUrgency, baseScore, baseSeverity, 
                                threatScore, threatSeverity, environmentalScore, environmentalSeverity);
                        
                        String source = rsV.getString(71);
                        CvssV4.Type cvssType = null;
                        value = rsV.getString(72);
                        if (value != null) {
                            cvssType = CvssV4.Type.fromValue(value);
                        }
                        
                        CvssV4 cvssv4 = new CvssV4(source, cvssType, data);
                        vuln.setCvssV4(cvssv4);
                    }
                    
                } else {
                    LOGGER.debug(cve + " does not exist in the database");
                    return null;
                }
            }
            try (PreparedStatement psCWE = getPreparedStatement(conn, SELECT_VULNERABILITY_CWE, cveId); ResultSet rsC = psCWE.executeQuery()) {
                while (rsC.next()) {
                    vuln.addCwe(rsC.getString(1));
                }
            }
            try (PreparedStatement psR = getPreparedStatement(conn, SELECT_REFERENCES, cveId); ResultSet rsR = psR.executeQuery()) {
                while (rsR.next()) {
                    vuln.addReference(rsR.getString(1), rsR.getString(2), rsR.getString(3));
                }
            }
            try (PreparedStatement psS = getPreparedStatement(conn, SELECT_SOFTWARE, cveId); ResultSet rsS = psS.executeQuery()) {
                //1 part, 2 vendor, 3 product, 4 version, 5 update_version, 6 edition, 7 lang,
                //8 sw_edition, 9 target_sw, 10 target_hw, 11 other, 12 versionEndExcluding,
                //13 versionEndIncluding, 14 versionStartExcluding, 15 versionStartIncluding, 16 vulnerable
                while (rsS.next()) {
                    vulnerableSoftwareBuilder.part(rsS.getString(1))
                            .vendor(rsS.getString(2))
                            .product(rsS.getString(3))
                            .version(rsS.getString(4))
                            .update(rsS.getString(5))
                            .edition(rsS.getString(6))
                            .language(rsS.getString(7))
                            .swEdition(rsS.getString(8))
                            .targetSw(rsS.getString(9))
                            .targetHw(rsS.getString(10))
                            .other(rsS.getString(11))
                            .versionEndExcluding(rsS.getString(12))
                            .versionEndIncluding(rsS.getString(13))
                            .versionStartExcluding(rsS.getString(14))
                            .versionStartIncluding(rsS.getString(15))
                            .vulnerable(rsS.getBoolean(16));
                    vuln.addVulnerableSoftware(vulnerableSoftwareBuilder.build());
                }
            }
        } catch (SQLException ex) {
            throw new DatabaseException("Error retrieving " + cve, ex);
        } catch (CpeParsingException | CpeValidationException ex) {
            throw new DatabaseException("The database contains an invalid Vulnerable Software Entry", ex);
        }
        return vuln;
    }

    /**
     * Updates the vulnerability within the database. If the vulnerability does
     * not exist it will be added.
     *
     * @param cve the vulnerability from the NVD CVE Data Feed to add to the
     * database
     * @param baseEcosystem the ecosystem the CVE belongs to; this is based off
     * of things like the CVE description
     * @throws DatabaseException is thrown if the database
     */
    public void updateVulnerability(DefCveItem cve, String baseEcosystem) {
        clearCache();
        final String cveId = cve.getCve().getId();
        try {
            if (cve.getCve().getVulnStatus().toUpperCase().startsWith("REJECT")) {
                deleteVulnerability(cveId);
            } else {
                if (cveItemConverter.testCveCpeStartWithFilter(cve)) {
                    final String description = cveItemConverter.extractDescription(cve);
                    final int vulnerabilityId = updateOrInsertVulnerability(cve, description);
                    updateVulnerabilityInsertCwe(vulnerabilityId, cve);
                    updateVulnerabilityInsertReferences(vulnerabilityId, cve);

                    final List<VulnerableSoftware> software = parseCpes(cve);
                    updateVulnerabilityInsertSoftware(vulnerabilityId, cveId, software, baseEcosystem);
                }
            }
        } catch (SQLException ex) {
            final String msg = String.format("Error updating '%s'; %s", cveId, ex.getMessage());
            LOGGER.debug(msg, ex);
            throw new DatabaseException(msg);
        } catch (CpeValidationException ex) {
            final String msg = String.format("Error parsing CPE entry from '%s'; %s", cveId, ex.getMessage());
            LOGGER.debug(msg, ex);
            throw new DatabaseException(msg);
        }
    }

    private void loadCpeEcosystemCache() {
        final Map<Pair<String, String>, String> map = new HashMap<>();
        try (Connection conn = databaseManager.getConnection();
                PreparedStatement ps = getPreparedStatement(conn, SELECT_CPE_ECOSYSTEM);
                ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                final Pair<String, String> key = new Pair<>(rs.getString(1), rs.getString(2));
                final String value = rs.getString(3);
                map.put(key, value);
            }
        } catch (SQLException ex) {
            final String msg = String.format("Error loading the Cpe Ecosystem Cache: %s", ex.getMessage());
            LOGGER.debug(msg, ex);
            throw new DatabaseException(msg, ex);
        }
        CpeEcosystemCache.setCache(map);
    }

    private void saveCpeEcosystemCache() {
        final Map<Pair<String, String>, String> map = CpeEcosystemCache.getChanged();
        if (map != null && !map.isEmpty()) {
            try (Connection conn = databaseManager.getConnection(); PreparedStatement ps = getPreparedStatement(conn, MERGE_CPE_ECOSYSTEM)) {
                for (Map.Entry<Pair<String, String>, String> entry : map.entrySet()) {
                    ps.setString(1, entry.getKey().getLeft());
                    ps.setString(2, entry.getKey().getRight());
                    ps.setString(3, entry.getValue());
                    if (isBatchInsertEnabled()) {
                        ps.addBatch();
                    } else {
                        ps.execute();
                    }
                }
                if (isBatchInsertEnabled()) {
                    ps.executeBatch();
                }
            } catch (SQLException ex) {
                final String msg = String.format("Error saving the Cpe Ecosystem Cache: %s", ex.getMessage());
                LOGGER.debug(msg, ex);
                throw new DatabaseException(msg, ex);
            }
        }
    }

    /**
     * Used when updating a vulnerability - this method inserts the
     * vulnerability entry itself.
     *
     * @param cve the CVE data
     * @param description the description of the CVE entry
     * @return the vulnerability ID
     */
    private int updateOrInsertVulnerability(DefCveItem cve, String description) {
        if (CpeEcosystemCache.isEmpty()) {
            loadCpeEcosystemCache();
        }
        final int vulnerabilityId;
        try (Connection conn = databaseManager.getConnection(); PreparedStatement callUpdate = getPreparedStatement(conn, UPDATE_VULNERABILITY)) {
//            String 1.cve, String 2.description, String 3.v2Severity, Float 4.v2ExploitabilityScore,
//            Float 5.v2ImpactScore, Boolean 6.v2AcInsufInfo, Boolean 7.v2ObtainAllPrivilege,
//            Boolean 8.v2ObtainUserPrivilege, Boolean 9.v2ObtainOtherPrivilege, Boolean 10.v2UserInteractionRequired,
//            Float 11.v2Score, String 12.v2AccessVector, String 13.v2AccessComplexity,
//            String 14.v2Authentication, String 15.v2ConfidentialityImpact, String 16.v2IntegrityImpact,
//            String 17.v2AvailabilityImpact, String 18.v2Version, Float 19.v3ExploitabilityScore,
//            Float 20.v3ImpactScore, String 21.v3AttackVector, String 22.v3AttackComplexity,
//            String 23.v3PrivilegesRequired, String 24.v3UserInteraction, String 25.v3Scope,
//            String 26.v3ConfidentialityImpact, String 27.v3IntegrityImpact, String 28.v3AvailabilityImpact,
//            Float 29.v3BaseScore, String 30.v3BaseSeverity, String 31.v3Version
// .          String 32.v4version, String 33.v4attackVector, String 34.v4attackComplexity, String 35.v4attackRequirements, 
//            String 36.v4privilegesRequired, String 37.v4userInteraction, String 38.v4vulnConfidentialityImpact, 
//            String 39.v4vulnIntegrityImpact, String 40.v4vulnAvailabilityImpact, String 41.v4subConfidentialityImpact, 
//            String 42.v4subIntegrityImpact, String 43.v4subAvailabilityImpact, String 44.v4exploitMaturity,
//            String 45.v4confidentialityRequirement, String 46.v4integrityRequirement, String 47.v4availabilityRequirement,
//            String 48.v4modifiedAttackVector, String 49.v4modifiedAttackComplexity, String 50.v4modifiedAttackRequirements,
//            String 51.v4modifiedPrivilegesRequired, String 52.v4modifiedUserInteraction, String 53.v4modifiedVulnConfidentialityImpact,
//            String 54.v4modifiedVulnIntegrityImpact, String 55.v4modifiedVulnAvailabilityImpact, String 56.v4modifiedSubConfidentialityImpact,
//            String 57.v4modifiedSubIntegrityImpact, String 58.v4modifiedSubAvailabilityImpact, String 59.v4safety,
//            String 60.v4automatable, String 61.v4recovery, String 62.v4valueDensity, String 63.v4vulnerabilityResponseEffort,
//            String 64.v4providerUrgency, Float 65.v4baseScore, String 66.v4baseSeverity, Float 67.v4threatScore,
//            String 68.v4threatSeverity, Float 69.v4environmentalScore, String 70.v4environmentalSeverity
// .          String 71.v4Source, String 72.v4type
            callUpdate.setString(1, cve.getCve().getId());
            callUpdate.setString(2, description);
            Optional<CvssV2> optCvssv2 = null;
            if (cve.getCve().getMetrics() != null && cve.getCve().getMetrics().getCvssMetricV2() != null) {
                optCvssv2 = cve.getCve().getMetrics().getCvssMetricV2().stream().sorted(Comparator.comparing(CvssV2::getType)).findFirst();
            }
            if (optCvssv2 != null && optCvssv2.isPresent()) {
                final CvssV2 cvssv2 = optCvssv2.get();
                setUpdateColumn(callUpdate, 3, cvssv2.getBaseSeverity());
                setUpdateColumn(callUpdate, 4, cvssv2.getExploitabilityScore());
                setUpdateColumn(callUpdate, 5, cvssv2.getImpactScore());
                setUpdateColumn(callUpdate, 6, cvssv2.getAcInsufInfo());
                setUpdateColumn(callUpdate, 7, cvssv2.getObtainAllPrivilege());
                setUpdateColumn(callUpdate, 8, cvssv2.getObtainUserPrivilege());
                setUpdateColumn(callUpdate, 9, cvssv2.getObtainOtherPrivilege());
                setUpdateColumn(callUpdate, 10, cvssv2.getUserInteractionRequired());
                setUpdateColumn(callUpdate, 11, cvssv2.getCvssData().getBaseScore());
                setUpdateColumn(callUpdate, 12, cvssv2.getCvssData().getAccessVector());
                setUpdateColumn(callUpdate, 13, cvssv2.getCvssData().getAccessComplexity());
                setUpdateColumn(callUpdate, 14, cvssv2.getCvssData().getAuthentication());
                setUpdateColumn(callUpdate, 15, cvssv2.getCvssData().getConfidentialityImpact());
                setUpdateColumn(callUpdate, 16, cvssv2.getCvssData().getIntegrityImpact());
                setUpdateColumn(callUpdate, 17, cvssv2.getCvssData().getAvailabilityImpact());
                setUpdateColumn(callUpdate, 18, cvssv2.getCvssData().getVersion());
            } else {
                callUpdate.setNull(3, java.sql.Types.VARCHAR);
                callUpdate.setNull(4, java.sql.Types.DOUBLE);
                callUpdate.setNull(5, java.sql.Types.DOUBLE);
                callUpdate.setNull(6, java.sql.Types.VARCHAR);
                //TODO this is may also be an issue for MS SQL, if an issue is created we'll just need
                // to create an isMsSQL flag. See todo below in setUpdateColum
                if (isOracle) {
                    callUpdate.setNull(7, java.sql.Types.BIT);
                    callUpdate.setNull(8, java.sql.Types.BIT);
                    callUpdate.setNull(9, java.sql.Types.BIT);
                    callUpdate.setNull(10, java.sql.Types.BIT);
                } else {
                    callUpdate.setNull(7, java.sql.Types.BOOLEAN);
                    callUpdate.setNull(8, java.sql.Types.BOOLEAN);
                    callUpdate.setNull(9, java.sql.Types.BOOLEAN);
                    callUpdate.setNull(10, java.sql.Types.BOOLEAN);
                }
                callUpdate.setNull(11, java.sql.Types.DOUBLE);
                callUpdate.setNull(12, java.sql.Types.VARCHAR);
                callUpdate.setNull(13, java.sql.Types.VARCHAR);
                callUpdate.setNull(14, java.sql.Types.VARCHAR);
                callUpdate.setNull(15, java.sql.Types.VARCHAR);
                callUpdate.setNull(16, java.sql.Types.VARCHAR);
                callUpdate.setNull(17, java.sql.Types.VARCHAR);
                callUpdate.setNull(18, java.sql.Types.VARCHAR);
            }
            Optional<CvssV3> optCvssv30 = Optional.empty();
            if (cve.getCve().getMetrics() != null && cve.getCve().getMetrics().getCvssMetricV30() != null) {
                optCvssv30 = cve.getCve().getMetrics().getCvssMetricV30().stream().sorted(Comparator.comparing(CvssV3::getType)).findFirst();
            }
            Optional<CvssV3> optCvssv31 = Optional.empty();
            if (cve.getCve().getMetrics() != null && cve.getCve().getMetrics().getCvssMetricV31() != null) {
                optCvssv31 = cve.getCve().getMetrics().getCvssMetricV31().stream().sorted(Comparator.comparing(CvssV3::getType)).findFirst();
            }

            CvssV3 cvssv3 = null;
            if (optCvssv31.isPresent()) {
                cvssv3 = optCvssv31.get();
            } else if (optCvssv30.isPresent()) {
                cvssv3 = optCvssv30.get();
            }
            if (cvssv3 != null) {
                setUpdateColumn(callUpdate, 19, cvssv3.getExploitabilityScore());
                setUpdateColumn(callUpdate, 20, cvssv3.getImpactScore());
                setUpdateColumn(callUpdate, 21, cvssv3.getCvssData().getAttackVector());
                setUpdateColumn(callUpdate, 22, cvssv3.getCvssData().getAttackComplexity());
                setUpdateColumn(callUpdate, 23, cvssv3.getCvssData().getPrivilegesRequired());
                setUpdateColumn(callUpdate, 24, cvssv3.getCvssData().getUserInteraction());
                setUpdateColumn(callUpdate, 25, cvssv3.getCvssData().getScope());
                setUpdateColumn(callUpdate, 26, cvssv3.getCvssData().getConfidentialityImpact());
                setUpdateColumn(callUpdate, 27, cvssv3.getCvssData().getIntegrityImpact());
                setUpdateColumn(callUpdate, 28, cvssv3.getCvssData().getAvailabilityImpact());
                setUpdateColumn(callUpdate, 29, cvssv3.getCvssData().getBaseScore());
                setUpdateColumn(callUpdate, 30, cvssv3.getCvssData().getBaseSeverity());
                setUpdateColumn(callUpdate, 31, cvssv3.getCvssData().getVersion());
            } else {
                callUpdate.setNull(19, java.sql.Types.DOUBLE);
                callUpdate.setNull(20, java.sql.Types.DOUBLE);
                callUpdate.setNull(21, java.sql.Types.VARCHAR);
                callUpdate.setNull(22, java.sql.Types.VARCHAR);
                callUpdate.setNull(23, java.sql.Types.VARCHAR);
                callUpdate.setNull(24, java.sql.Types.VARCHAR);
                callUpdate.setNull(25, java.sql.Types.VARCHAR);
                callUpdate.setNull(26, java.sql.Types.VARCHAR);
                callUpdate.setNull(27, java.sql.Types.VARCHAR);
                callUpdate.setNull(28, java.sql.Types.VARCHAR);
                callUpdate.setNull(29, java.sql.Types.DOUBLE);
                callUpdate.setNull(30, java.sql.Types.VARCHAR);
                callUpdate.setNull(31, java.sql.Types.VARCHAR);
            }

            Optional<CvssV4> optCvssv4 = null;
            if (cve.getCve().getMetrics() != null && cve.getCve().getMetrics().getCvssMetricV40() != null) {
                optCvssv4 = cve.getCve().getMetrics().getCvssMetricV40().stream().sorted(Comparator.comparing(CvssV4::getType)).findFirst();
            }
            if (optCvssv4 != null && optCvssv4.isPresent()) {
                CvssV4 cvssv4 = optCvssv4.get();
                setUpdateColumn(callUpdate, 32, cvssv4.getCvssData().getVersion());
                setUpdateColumn(callUpdate, 33, cvssv4.getCvssData().getAttackVector());
                setUpdateColumn(callUpdate, 34, cvssv4.getCvssData().getAttackComplexity());
                setUpdateColumn(callUpdate, 35, cvssv4.getCvssData().getAttackRequirements());
                setUpdateColumn(callUpdate, 36, cvssv4.getCvssData().getPrivilegesRequired());
                setUpdateColumn(callUpdate, 37, cvssv4.getCvssData().getUserInteraction());
                setUpdateColumn(callUpdate, 38, cvssv4.getCvssData().getVulnConfidentialityImpact());
                setUpdateColumn(callUpdate, 39, cvssv4.getCvssData().getVulnIntegrityImpact());
                setUpdateColumn(callUpdate, 40, cvssv4.getCvssData().getVulnAvailabilityImpact());
                setUpdateColumn(callUpdate, 41, cvssv4.getCvssData().getSubConfidentialityImpact());
                setUpdateColumn(callUpdate, 42, cvssv4.getCvssData().getSubIntegrityImpact());
                setUpdateColumn(callUpdate, 43, cvssv4.getCvssData().getSubAvailabilityImpact());
                setUpdateColumn(callUpdate, 44, cvssv4.getCvssData().getExploitMaturity());
                setUpdateColumn(callUpdate, 45, cvssv4.getCvssData().getConfidentialityRequirement());
                setUpdateColumn(callUpdate, 46, cvssv4.getCvssData().getIntegrityRequirement());
                setUpdateColumn(callUpdate, 47, cvssv4.getCvssData().getAvailabilityRequirement());
                setUpdateColumn(callUpdate, 48, cvssv4.getCvssData().getModifiedAttackVector());
                setUpdateColumn(callUpdate, 49, cvssv4.getCvssData().getModifiedAttackComplexity());
                setUpdateColumn(callUpdate, 50, cvssv4.getCvssData().getModifiedAttackRequirements());
                setUpdateColumn(callUpdate, 51, cvssv4.getCvssData().getModifiedPrivilegesRequired());
                setUpdateColumn(callUpdate, 52, cvssv4.getCvssData().getModifiedUserInteraction());
                setUpdateColumn(callUpdate, 53, cvssv4.getCvssData().getModifiedVulnConfidentialityImpact());
                setUpdateColumn(callUpdate, 54, cvssv4.getCvssData().getModifiedVulnIntegrityImpact());
                setUpdateColumn(callUpdate, 55, cvssv4.getCvssData().getModifiedVulnAvailabilityImpact());
                setUpdateColumn(callUpdate, 56, cvssv4.getCvssData().getModifiedSubConfidentialityImpact());
                setUpdateColumn(callUpdate, 57, cvssv4.getCvssData().getModifiedSubIntegrityImpact());
                setUpdateColumn(callUpdate, 58, cvssv4.getCvssData().getModifiedSubAvailabilityImpact());
                setUpdateColumn(callUpdate, 59, cvssv4.getCvssData().getSafety());
                setUpdateColumn(callUpdate, 60, cvssv4.getCvssData().getAutomatable());
                setUpdateColumn(callUpdate, 61, cvssv4.getCvssData().getRecovery());
                setUpdateColumn(callUpdate, 62, cvssv4.getCvssData().getValueDensity());
                setUpdateColumn(callUpdate, 63, cvssv4.getCvssData().getVulnerabilityResponseEffort());
                setUpdateColumn(callUpdate, 64, cvssv4.getCvssData().getProviderUrgency());
                setUpdateColumn(callUpdate, 65, cvssv4.getCvssData().getBaseScore());
                setUpdateColumn(callUpdate, 66, cvssv4.getCvssData().getBaseSeverity());
                setUpdateColumn(callUpdate, 67, cvssv4.getCvssData().getThreatScore());
                setUpdateColumn(callUpdate, 68, cvssv4.getCvssData().getThreatSeverity());
                setUpdateColumn(callUpdate, 69, cvssv4.getCvssData().getEnvironmentalScore());
                setUpdateColumn(callUpdate, 70, cvssv4.getCvssData().getEnvironmentalSeverity());
                setUpdateColumn(callUpdate, 71, cvssv4.getSource());
                setUpdateColumn(callUpdate, 72, cvssv4.getType());
            } else {
                callUpdate.setNull(32, java.sql.Types.VARCHAR);
                callUpdate.setNull(33, java.sql.Types.VARCHAR);
                callUpdate.setNull(34, java.sql.Types.VARCHAR);
                callUpdate.setNull(35, java.sql.Types.VARCHAR);
                callUpdate.setNull(36, java.sql.Types.VARCHAR);
                callUpdate.setNull(37, java.sql.Types.VARCHAR);
                callUpdate.setNull(38, java.sql.Types.VARCHAR);
                callUpdate.setNull(39, java.sql.Types.VARCHAR);
                callUpdate.setNull(40, java.sql.Types.VARCHAR);
                callUpdate.setNull(41, java.sql.Types.VARCHAR);
                callUpdate.setNull(42, java.sql.Types.VARCHAR);
                callUpdate.setNull(43, java.sql.Types.VARCHAR);
                callUpdate.setNull(44, java.sql.Types.VARCHAR);
                callUpdate.setNull(45, java.sql.Types.VARCHAR);
                callUpdate.setNull(46, java.sql.Types.VARCHAR);
                callUpdate.setNull(47, java.sql.Types.VARCHAR);
                callUpdate.setNull(48, java.sql.Types.VARCHAR);
                callUpdate.setNull(49, java.sql.Types.VARCHAR);
                callUpdate.setNull(50, java.sql.Types.VARCHAR);
                callUpdate.setNull(51, java.sql.Types.VARCHAR);
                callUpdate.setNull(52, java.sql.Types.VARCHAR);
                callUpdate.setNull(53, java.sql.Types.VARCHAR);
                callUpdate.setNull(54, java.sql.Types.VARCHAR);
                callUpdate.setNull(55, java.sql.Types.VARCHAR);
                callUpdate.setNull(56, java.sql.Types.VARCHAR);
                callUpdate.setNull(57, java.sql.Types.VARCHAR);
                callUpdate.setNull(58, java.sql.Types.VARCHAR);
                callUpdate.setNull(59, java.sql.Types.VARCHAR);
                callUpdate.setNull(60, java.sql.Types.VARCHAR);
                callUpdate.setNull(61, java.sql.Types.VARCHAR);
                callUpdate.setNull(62, java.sql.Types.VARCHAR);
                callUpdate.setNull(63, java.sql.Types.VARCHAR);
                callUpdate.setNull(64, java.sql.Types.VARCHAR);
                callUpdate.setNull(65, java.sql.Types.DOUBLE);
                callUpdate.setNull(66, java.sql.Types.VARCHAR);
                callUpdate.setNull(67, java.sql.Types.DOUBLE);
                callUpdate.setNull(68, java.sql.Types.VARCHAR);
                callUpdate.setNull(69, java.sql.Types.DOUBLE);
                callUpdate.setNull(70, java.sql.Types.VARCHAR);
                callUpdate.setNull(71, java.sql.Types.VARCHAR);
                callUpdate.setNull(72, java.sql.Types.VARCHAR);
            }
            if (isOracle) {
                try {
                    final CallableStatement cs = (CallableStatement) callUpdate;
                    cs.registerOutParameter(73, JDBCType.INTEGER);
                    cs.executeUpdate();
                    vulnerabilityId = cs.getInt(73);
                } catch (SQLException ex) {
                    final String msg = String.format("Unable to retrieve id for new vulnerability for '%s'", cve.getCve().getId());
                    throw new DatabaseException(msg, ex);
                }
            } else {
                try (ResultSet rs = callUpdate.executeQuery()) {
                    rs.next();
                    vulnerabilityId = rs.getInt(1);
                } catch (SQLException ex) {
                    final String msg = String.format("Unable to retrieve id for new vulnerability for '%s'", cve.getCve().getId());
                    throw new DatabaseException(msg, ex);
                }
            }
        } catch (SQLException ex) {
            throw new UnexpectedAnalysisException(ex);
        }
        return vulnerabilityId;
    }

    /**
     * Used when updating a vulnerability - this method inserts the CWE entries.
     *
     * @param vulnerabilityId the vulnerability ID
     * @param cve the CVE entry that contains the CWE entries to insert
     * @throws SQLException thrown if there is an error inserting the data
     */
    private void updateVulnerabilityInsertCwe(int vulnerabilityId, DefCveItem cve) throws SQLException {
        if (cve.getCve() != null && cve.getCve().getWeaknesses() != null) {
            try (Connection conn = databaseManager.getConnection();
                    PreparedStatement insertCWE = getPreparedStatement(conn, INSERT_CWE, vulnerabilityId)) {
                for (Weakness weakness : cve.getCve().getWeaknesses()) {
                    for (LangString desc : weakness.getDescription()) {
                        if ("en".equals(desc.getLang())) {
                            insertCWE.setString(2, desc.getValue());
                            if (isBatchInsertEnabled()) {
                                insertCWE.addBatch();
                            } else {
                                insertCWE.execute();
                            }
                        }
                    }
                }
                if (isBatchInsertEnabled()) {
                    insertCWE.executeBatch();
                }
            }
        }
    }

    /**
     * Used when updating a vulnerability - in some cases a CVE needs to be
     * removed.
     *
     * @param cve the vulnerability CVE
     * @throws SQLException thrown if there is an error deleting the
     * vulnerability
     */
    private void deleteVulnerability(String cve) throws SQLException {
        try (Connection conn = databaseManager.getConnection();
                PreparedStatement deleteVulnerability = getPreparedStatement(conn, DELETE_VULNERABILITY, cve)) {
            deleteVulnerability.executeUpdate();
        }
    }

    /**
     * Merges the list of known exploited vulnerabilities into the database.
     *
     * @param vulnerabilities the list of known exploited vulnerabilities
     * @throws DatabaseException thrown if there is an exception... duh..
     * @throws SQLException thrown if there is an exception... duh..
     */
    public void updateKnownExploitedVulnerabilities(
            List<org.owasp.dependencycheck.data.knownexploited.json.Vulnerability> vulnerabilities)
            throws DatabaseException, SQLException {
        try (Connection conn = databaseManager.getConnection();
                PreparedStatement mergeKnownVulnerability = getPreparedStatement(conn, MERGE_KNOWN_EXPLOITED)) {
            int ctr = 0;
            for (org.owasp.dependencycheck.data.knownexploited.json.Vulnerability v : vulnerabilities) {
                mergeKnownVulnerability.setString(1, v.getCveID());
                addNullableStringParameter(mergeKnownVulnerability, 2, v.getVendorProject());
                addNullableStringParameter(mergeKnownVulnerability, 3, v.getProduct());
                addNullableStringParameter(mergeKnownVulnerability, 4, v.getVulnerabilityName());
                addNullableStringParameter(mergeKnownVulnerability, 5, v.getDateAdded());
                addNullableStringParameter(mergeKnownVulnerability, 6, v.getShortDescription());
                addNullableStringParameter(mergeKnownVulnerability, 7, v.getRequiredAction());
                addNullableStringParameter(mergeKnownVulnerability, 8, v.getDueDate());
                addNullableStringParameter(mergeKnownVulnerability, 9, v.getNotes());
                if (isBatchInsertEnabled()) {
                    mergeKnownVulnerability.addBatch();
                    ctr++;
                    if (ctr >= getBatchSize()) {
                        mergeKnownVulnerability.executeBatch();
                        ctr = 0;
                    }
                } else {
                    try {
                        mergeKnownVulnerability.execute();
                    } catch (SQLException ex) {
                        if (ex.getMessage().contains("Duplicate entry")) {
                            final String msg = String.format("Duplicate known exploited vulnerability key identified in '%s'", v.getCveID());
                            LOGGER.info(msg, ex);
                        } else {
                            throw ex;
                        }
                    }
                }
            }
            if (isBatchInsertEnabled()) {
                mergeKnownVulnerability.executeBatch();
            }
        }
    }

    /**
     * Used when updating a vulnerability - this method inserts the list of
     * vulnerable software.
     *
     * @param vulnerabilityId the vulnerability id
     * @param cveId the CVE ID - used for reporting
     * @param software the list of vulnerable software
     * @param baseEcosystem the ecosystem based off of the vulnerability
     * description
     * @throws DatabaseException thrown if there is an error inserting the data
     * @throws SQLException thrown if there is an error inserting the data
     */
    private void updateVulnerabilityInsertSoftware(int vulnerabilityId, String cveId,
            List<VulnerableSoftware> software, String baseEcosystem)
            throws DatabaseException, SQLException {
        try (Connection conn = databaseManager.getConnection(); PreparedStatement insertSoftware = getPreparedStatement(conn, INSERT_SOFTWARE)) {
            for (VulnerableSoftware parsedCpe : software) {
                insertSoftware.setInt(1, vulnerabilityId);
                insertSoftware.setString(2, parsedCpe.getPart().getAbbreviation());
                insertSoftware.setString(3, parsedCpe.getVendor());
                insertSoftware.setString(4, parsedCpe.getProduct());
                insertSoftware.setString(5, parsedCpe.getVersion());
                insertSoftware.setString(6, parsedCpe.getUpdate());
                insertSoftware.setString(7, parsedCpe.getEdition());
                insertSoftware.setString(8, parsedCpe.getLanguage());
                insertSoftware.setString(9, parsedCpe.getSwEdition());
                insertSoftware.setString(10, parsedCpe.getTargetSw());
                insertSoftware.setString(11, parsedCpe.getTargetHw());
                insertSoftware.setString(12, parsedCpe.getOther());
                final String ecosystem = CpeEcosystemCache.getEcosystem(parsedCpe.getVendor(), parsedCpe.getProduct(),
                        cveItemConverter.extractEcosystem(baseEcosystem, parsedCpe));

                addNullableStringParameter(insertSoftware, 13, ecosystem);
                addNullableStringParameter(insertSoftware, 14, parsedCpe.getVersionEndExcluding());
                addNullableStringParameter(insertSoftware, 15, parsedCpe.getVersionEndIncluding());
                addNullableStringParameter(insertSoftware, 16, parsedCpe.getVersionStartExcluding());
                addNullableStringParameter(insertSoftware, 17, parsedCpe.getVersionStartIncluding());
                insertSoftware.setBoolean(18, parsedCpe.isVulnerable());

                if (isBatchInsertEnabled()) {
                    insertSoftware.addBatch();
                } else {
                    try {
                        insertSoftware.execute();
                    } catch (SQLException ex) {
                        if (ex.getMessage().contains("Duplicate entry")) {
                            final String msg = String.format("Duplicate software key identified in '%s'", cveId);
                            LOGGER.info(msg, ex);
                        } else {
                            throw ex;
                        }
                    }
                }
            }
            if (isBatchInsertEnabled()) {
                executeBatch(cveId, insertSoftware);
            }
        }
    }

    /**
     * Used when updating a vulnerability - this method inserts the list of
     * references.
     *
     * @param vulnerabilityId the vulnerability id
     * @param cve the CVE entry that contains the list of references
     * @throws SQLException thrown if there is an error inserting the data
     */
    private void updateVulnerabilityInsertReferences(int vulnerabilityId, DefCveItem cve) throws SQLException {
        try (Connection conn = databaseManager.getConnection(); PreparedStatement insertReference = getPreparedStatement(conn, INSERT_REFERENCE)) {
            if (cve.getCve().getReferences() != null) {
                for (Reference r : cve.getCve().getReferences()) {
                    insertReference.setInt(1, vulnerabilityId);
                    String name = null;
                    if (r.getTags() != null) {
                        name = r.getTags().stream().sorted().collect(Collectors.joining(",")).toUpperCase().replaceAll("\\s", "_");
                    }
                    if (name != null) {
                        insertReference.setString(2, name);
                    } else {
                        insertReference.setNull(2, java.sql.Types.VARCHAR);
                    }
                    if (r.getUrl() != null && !r.getUrl().isEmpty()) {
                        insertReference.setString(3, r.getUrl());
                    } else {
                        insertReference.setNull(3, java.sql.Types.VARCHAR);
                    }
                    if (r.getSource() != null && !r.getSource().isEmpty()) {
                        insertReference.setString(4, r.getSource());
                    } else {
                        insertReference.setNull(4, java.sql.Types.VARCHAR);
                    }
                    if (isBatchInsertEnabled()) {
                        insertReference.addBatch();
                    } else {
                        insertReference.execute();
                    }
                }
            }
            if (isBatchInsertEnabled()) {
                insertReference.executeBatch();
            }
        }
    }

    /**
     * Parses the configuration entries from the CVE entry into a list of
     * VulnerableSoftware objects.
     *
     * @param cve the CVE to parse the vulnerable software entries from
     * @return the list of vulnerable software
     * @throws CpeValidationException if an invalid CPE is present
     */
    private List<VulnerableSoftware> parseCpes(DefCveItem cve) throws CpeValidationException {
        final List<VulnerableSoftware> software = new ArrayList<>();

        final List<CpeMatch> cpeEntries = cve.getCve().getConfigurations().stream()
                .map(Config::getNodes)
                .flatMap(List::stream)
                .map(Node::getCpeMatch)
                .flatMap(List::stream)
                .filter(predicate -> predicate.getCriteria() != null)
                .filter(predicate -> predicate.getCriteria().startsWith(cpeStartsWithFilter))
                //this single CPE entry causes nearly 100% FP - so filtering it at the source.
                .filter(entry -> !("CVE-2009-0754".equals(cve.getCve().getId())
                && "cpe:2.3:a:apache:apache:*:*:*:*:*:*:*:*".equals(entry.getCriteria())))
                .collect(Collectors.toList());
        final VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();

        try {
            cpeEntries.forEach(entry -> {
                builder.cpe(parseCpe(entry, cve.getCve().getId()))
                        .versionEndExcluding(entry.getVersionEndExcluding())
                        .versionStartExcluding(entry.getVersionStartExcluding())
                        .versionEndIncluding(entry.getVersionEndIncluding())
                        .versionStartIncluding(entry.getVersionStartIncluding())
                        .vulnerable(entry.getVulnerable());
                try {
                    software.add(builder.build());
                } catch (CpeValidationException ex) {
                    throw new LambdaExceptionWrapper(ex);
                }
            });
        } catch (LambdaExceptionWrapper ex) {
            throw (CpeValidationException) ex.getCause();
        }
        return software;
    }

    /**
     * Helper method to convert a CpeMatch (generated code used in parsing the
     * NVD JSON) into a CPE object.
     *
     * @param cpe the CPE Match
     * @param cveId the CVE associated with the CPEMatch - used for error
     * reporting
     * @return the resulting CPE object
     * @throws DatabaseException thrown if there is an error converting the
     * CpeMatch into a CPE object
     */
    private Cpe parseCpe(CpeMatch cpe, String cveId) throws DatabaseException {
        final Cpe parsedCpe;
        try {
            //the replace is a hack as the NVD does not properly escape backslashes in their JSON
            parsedCpe = CpeParser.parse(cpe.getCriteria(), true);
        } catch (CpeParsingException ex) {
            LOGGER.debug("NVD (" + cveId + ") contain an invalid 2.3 CPE: " + cpe.getCriteria());
            throw new DatabaseException("Unable to parse CPE: " + cpe.getCriteria(), ex);
        }
        return parsedCpe;
    }

    /**
     * Returns the size of the batch.
     *
     * @return the size of the batch
     */
    private int getBatchSize() {
        int max;
        try {
            max = settings.getInt(Settings.KEYS.MAX_BATCH_SIZE);
        } catch (InvalidSettingException pE) {
            max = 1000;
        }
        return max;
    }

    /**
     * Determines whether or not batch insert is enabled.
     *
     * @return <code>true</code> if batch insert is enabled; otherwise
     * <code>false</code>
     */
    private boolean isBatchInsertEnabled() {
        boolean batch;
        try {
            batch = settings.getBoolean(Settings.KEYS.ENABLE_BATCH_UPDATES);
        } catch (InvalidSettingException pE) {
            //If there's no configuration, default is to not perform batch inserts
            batch = false;
        }
        return batch;
    }

    /**
     * Executes batch inserts of vulnerabilities when property
     * database.batchinsert.maxsize is reached.
     *
     * @param vulnId the vulnerability ID
     * @param statement the prepared statement to batch execute
     * @throws SQLException thrown when the batch cannot be executed
     */
    private void executeBatch(String vulnId, PreparedStatement statement)
            throws SQLException {
        try {
            statement.executeBatch();
        } catch (SQLException ex) {
            if (ex.getMessage().contains("Duplicate entry")) {
                final String msg = String.format("Duplicate software key identified in '%s'",
                        vulnId);
                LOGGER.info(msg, ex);
            } else {
                throw ex;
            }
        }
    }

    /**
     * Checks to see if data exists so that analysis can be performed.
     *
     * @return <code>true</code> if data exists; otherwise <code>false</code>
     */
    public boolean dataExists() {
        try (Connection conn = databaseManager.getConnection();
                PreparedStatement cs = getPreparedStatement(conn, COUNT_CPE);
                ResultSet rs = cs.executeQuery()) {
            if (rs.next() && rs.getInt(1) > 0) {
                return true;
            }
        } catch (Exception ex) {
            String dd;
            try {
                dd = settings.getDataDirectory().getAbsolutePath();
            } catch (IOException ex1) {
                dd = settings.getString(Settings.KEYS.DATA_DIRECTORY);
            }
            LOGGER.error("Unable to access the local database.\n\nEnsure that '{}' is a writable directory. "
                    + "If the problem persist try deleting the files in '{}' and running {} again. If the problem continues, please "
                    + "create a log file (see documentation at https://jeremylong.github.io/DependencyCheck/) and open a ticket at "
                    + "https://github.com/jeremylong/DependencyCheck/issues and include the log file.\n\n",
                    dd, dd, settings.getString(Settings.KEYS.APPLICATION_NAME));
            LOGGER.debug("", ex);
        }
        return false;
    }

    /**
     * It is possible that orphaned rows may be generated during database
     * updates. This should be called after all updates have been completed to
     * ensure orphan entries are removed.
     */
    public void cleanupDatabase() {
        LOGGER.info("Begin database maintenance");
        final long start = System.currentTimeMillis();
        try (Connection conn = databaseManager.getConnection();
                PreparedStatement psOrphans = getPreparedStatement(conn, CLEANUP_ORPHANS);
                PreparedStatement psEcosystem = getPreparedStatement(conn, UPDATE_ECOSYSTEM);
                PreparedStatement psEcosystem2 = getPreparedStatement(conn, UPDATE_ECOSYSTEM2)) {
            if (psEcosystem != null) {
                final int count = psEcosystem.executeUpdate();
                if (count > 0) {
                    LOGGER.info("Updated the CPE ecosystem on {} NVD records", count);
                }
            }
            if (psEcosystem2 != null) {
                final int count = psEcosystem2.executeUpdate();
                if (count > 0) {
                    LOGGER.info("Removed the CPE ecosystem on {} NVD records", count);
                }
            }
            if (psOrphans != null) {
                final int count = psOrphans.executeUpdate();
                if (count > 0) {
                    LOGGER.info("Cleaned up {} orphaned NVD records", count);
                }
            }
            final long millis = System.currentTimeMillis() - start;
            //final long seconds = TimeUnit.MILLISECONDS.toSeconds(millis);
            LOGGER.info("End database maintenance ({} ms)", millis);
        } catch (SQLException ex) {
            LOGGER.error("An unexpected SQL Exception occurred; please see the verbose log for more details.");
            LOGGER.debug("", ex);
            throw new DatabaseException("Unexpected SQL Exception", ex);
        }
    }

    /**
     * Persist the EcosystemCache into the database.
     */
    public void persistEcosystemCache() {
        saveCpeEcosystemCache();
        clearCache();
    }

    /**
     * If the database is using an H2 file based database calling
     * <code>defrag()</code> will de-fragment the database.
     */
    public void defrag() {
        if (isH2) {
            final long start = System.currentTimeMillis();
            try (Connection conn = databaseManager.getConnection(); CallableStatement psCompaxt = conn.prepareCall("SHUTDOWN DEFRAG")) {
                LOGGER.info("Begin database defrag");
                psCompaxt.execute();
                final long millis = System.currentTimeMillis() - start;
                //final long seconds = TimeUnit.MILLISECONDS.toSeconds(millis);
                LOGGER.info("End database defrag ({} ms)", millis);
            } catch (SQLException ex) {
                LOGGER.error("An unexpected SQL Exception occurred compacting the database; please see the verbose log for more details.");
                LOGGER.debug("", ex);
            }
        }
    }

    /**
     * Determines if the given identifiedVersion is affected by the given cpeId
     * and previous version flag. A non-null, non-empty string passed to the
     * previous version argument indicates that all previous versions are
     * affected.
     *
     * @param cpe the CPE for the given dependency
     * @param vulnerableSoftware a set of the vulnerable software
     * @return true if the identified version is affected, otherwise false
     */
    VulnerableSoftware getMatchingSoftware(Cpe cpe, Set<VulnerableSoftware> vulnerableSoftware) {
        VulnerableSoftware matched = null;
        for (VulnerableSoftware vs : vulnerableSoftware) {
            if (vs.matches(cpe)) {
                if (matched == null) {
                    matched = vs;
                } else {
                    if ("*".equals(vs.getWellFormedUpdate()) && !"*".equals(matched.getWellFormedUpdate())) {
                        matched = vs;
                    }
                }
            }
        }
        return matched;
    }

    /**
     * This method is only referenced in unused code.
     * <p>
     * Deletes unused dictionary entries from the database.
     * </p>
     */
    public void deleteUnusedCpe() {
        clearCache();
        try (Connection conn = databaseManager.getConnection(); PreparedStatement ps = getPreparedStatement(conn, DELETE_UNUSED_DICT_CPE)) {
            ps.executeUpdate();
        } catch (SQLException ex) {
            LOGGER.error("Unable to delete CPE dictionary entries", ex);
        }
    }

    /**
     * This method is only referenced in unused code and will likely break on
     * MySQL if ever used due to the MERGE statement.
     * <p>
     * Merges CPE entries into the database.
     * </p>
     *
     * @param cpe the CPE identifier
     * @param vendor the CPE vendor
     * @param product the CPE product
     */
    public void addCpe(String cpe, String vendor, String product) {
        clearCache();
        try (Connection conn = databaseManager.getConnection(); PreparedStatement ps = getPreparedStatement(conn, ADD_DICT_CPE)) {
            ps.setString(1, cpe);
            ps.setString(2, vendor);
            ps.setString(3, product);
            ps.executeUpdate();
        } catch (SQLException ex) {
            LOGGER.error("Unable to add CPE dictionary entry", ex);
        }
    }

    /**
     * Returns a map of known exploited vulnerabilities.
     *
     * @return a map of known exploited vulnerabilities
     */
    public Map<String, org.owasp.dependencycheck.data.knownexploited.json.Vulnerability> getknownExploitedVulnerabilities() {
        final Map<String, org.owasp.dependencycheck.data.knownexploited.json.Vulnerability> known = new HashMap<>();

        try (Connection conn = databaseManager.getConnection();
                PreparedStatement ps = getPreparedStatement(conn, SELECT_KNOWN_EXPLOITED_VULNERABILITIES);
                ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                final org.owasp.dependencycheck.data.knownexploited.json.Vulnerability kev =
                        new org.owasp.dependencycheck.data.knownexploited.json.Vulnerability();
                kev.setCveID(rs.getString(1));
                kev.setVendorProject(rs.getString(2));
                kev.setProduct(rs.getString(3));
                kev.setVulnerabilityName(rs.getString(4));
                kev.setDateAdded(rs.getString(5));
                kev.setShortDescription(rs.getString(6));
                kev.setRequiredAction(rs.getString(7));
                kev.setDueDate(rs.getString(8));
                kev.setNotes(rs.getString(9));
                known.put(kev.getCveID(), kev);
            }

        } catch (SQLException ex) {
            throw new DatabaseException(ex);
        }
        return known;
    }

    /**
     * Helper method to add a nullable string parameter.
     *
     * @param ps the prepared statement
     * @param pos the position of the parameter
     * @param value the value of the parameter
     * @throws SQLException thrown if there is an error setting the parameter.
     */
    private void addNullableStringParameter(PreparedStatement ps, int pos, String value) throws SQLException {
        if (value == null || value.isEmpty()) {
            ps.setNull(pos, java.sql.Types.VARCHAR);
        } else {
            ps.setString(pos, value);
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, Double value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.DOUBLE);
        } else {
            ps.setDouble(i, value);
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV2Data.AuthenticationType value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV2Data.CiaType value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV2Data.Version value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV2Data.AccessComplexityType value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV2Data.AccessVectorType value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, String value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value);
        }
    }
    
    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4.Type value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, Boolean value) throws SQLException {
        if (value == null) {
            //TODO this is may also be an issue for MS SQL, if an issue is created we'll just need
            // to create an isMsSQL flag. See todo above in updateOrInsertVulnerability.
            if (isOracle) {
                ps.setNull(i, java.sql.Types.BIT);
            } else {
                ps.setNull(i, java.sql.Types.BOOLEAN);
            }
        } else {
            ps.setBoolean(i, value);
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV3Data.AttackVectorType value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV3Data.AttackComplexityType value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV3Data.PrivilegesRequiredType value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV3Data.UserInteractionType value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV3Data.ScopeType value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV3Data.SeverityType value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV3Data.CiaType value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV3Data.Version value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.Version value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.AttackVectorType value) throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.AttackComplexityType value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.AttackRequirementsType value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.PrivilegesRequiredType value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.UserInteractionType value)  throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.CiaType value)  throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.ExploitMaturityType value)  throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.CiaRequirementType value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.ModifiedAttackVectorType value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.ModifiedAttackComplexityType value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.ModifiedAttackRequirementsType value)  throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.ModifiedPrivilegesRequiredType value)  throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.ModifiedUserInteractionType value)  throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.ModifiedCiaType value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.SafetyType value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.AutomatableType value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.RecoveryType value)  throws SQLException {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.ValueDensityType value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.VulnerabilityResponseEffortType value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.ProviderUrgencyType value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    private void setUpdateColumn(PreparedStatement ps, int i, CvssV4Data.SeverityType value) throws SQLException  {
        if (value == null) {
            ps.setNull(i, java.sql.Types.VARCHAR);
        } else {
            ps.setString(i, value.value());
        }
    }

    /**
     * Sets the float parameter on a prepared statement from a properties map.
     *
     * @param ps a prepared statement
     * @param i the index of the property
     * @param props the property collection
     * @param key the property key
     * @throws SQLException thrown if there is an error adding the property
     */
    private void setFloatValue(PreparedStatement ps, int i, Map<String, Object> props, String key) throws SQLException {
        if (props != null && props.containsKey(key)) {
            try {
                ps.setFloat(i, Float.parseFloat(props.get(key).toString()));
            } catch (NumberFormatException nfe) {
                ps.setNull(i, java.sql.Types.FLOAT);
            }
        } else {
            ps.setNull(i, java.sql.Types.FLOAT);
        }
    }

    /**
     * Sets the string parameter on a prepared statement from a properties map.
     *
     * @param ps a prepared statement
     * @param i the index of the property
     * @param props the property collection
     * @param key the property key
     * @throws SQLException thrown if there is an error adding the property
     */
    private void setStringValue(PreparedStatement ps, int i, Map<String, Object> props, String key) throws SQLException {
        if (props != null && props.containsKey(key)) {
            ps.setString(i, props.get(key).toString());
        } else {
            ps.setNull(i, java.sql.Types.VARCHAR);
        }
    }

    /**
     * Sets the boolean parameter on a prepared statement from a properties map.
     *
     * @param ps a prepared statement
     * @param i the index of the property
     * @param props the property collection
     * @param key the property key
     * @throws SQLException thrown if there is an error adding the property
     */
    private void setBooleanValue(PreparedStatement ps, int i, Map<String, Object> props, String key) throws SQLException {
        if (props != null && props.containsKey(key)) {
            ps.setBoolean(i, Boolean.parseBoolean(props.get(key).toString()));
        } else {
            ps.setNull(i, java.sql.Types.BOOLEAN);
        }
    }

    /**
     * Returns the Boolean value for the given index; if the value is null then
     * null is returned.
     *
     * @param rs the record set
     * @param index the parameter index
     * @return the Boolean value; or null
     * @throws SQLException thrown if there is an error obtaining the value
     */
    @SuppressFBWarnings("NP_BOOLEAN_RETURN_NULL")
    private Boolean getBooleanValue(ResultSet rs, int index) throws SQLException {
        if (rs.getObject(index) == null) {
            return null;
        }
        return rs.getBoolean(index);
    }

    /**
     * Returns the Float value for the given index; if the value is null then
     * null is returned.
     *
     * @param rs the record set
     * @param index the parameter index
     * @return the Float value; or null
     * @throws SQLException thrown if there is an error obtaining the value
     */
    private Float getFloatValue(ResultSet rs, int index) throws SQLException {
        if (rs.getObject(index) == null) {
            return null;
        }
        return rs.getFloat(index);
    }
}
