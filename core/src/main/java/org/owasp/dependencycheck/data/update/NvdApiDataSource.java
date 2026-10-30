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
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import io.github.jeremylong.openvulnerability.client.nvd.NvdApiException;
import io.github.jeremylong.openvulnerability.client.nvd.NvdCveClient;
import io.github.jeremylong.openvulnerability.client.nvd.NvdCveClientBuilder;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.NonNull;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.data.update.nvd.api.DownloadTask;
import org.owasp.dependencycheck.data.update.nvd.api.NvdApiProcessor;
import org.owasp.dependencycheck.utils.DateUtil;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Pair;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.MessageFormat;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;
import java.util.zip.GZIPOutputStream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.MINUTES;

/**
 *
 * @author Jeremy Long
 */
public class NvdApiDataSource implements CachedWebDataSource {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NvdApiDataSource.class);
    /**
     * The thread pool size to use for CPU-intense tasks.
     */
    private static final int DEFAULT_PROCESSING_THREAD_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    /**
     * The configured settings.
     */
    private Settings settings;
    /**
     * Reference to the DAO.
     */
    private CveDB cveDb = null;
    /**
     * The properties obtained from the database.
     */
    private DatabaseProperties dbProperties = null;
    /**
     * The key for the NVD API cache properties file's last modified date.
     */
    private static final String NVD_API_CACHE_MODIFIED_DATE = "lastModifiedDate";
    /**
     * The number of results per page from the NVD API. The default is 2000; we
     * are setting the value to be explicit.
     */
    private static final int RESULTS_PER_PAGE = 2000;

    @Override
    public boolean update(Engine engine) throws UpdateException {
        this.settings = engine.getSettings();
        this.cveDb = engine.getDatabase();
        if (isUpdateConfiguredFalse()) {
            return false;
        }
        dbProperties = cveDb.getDatabaseProperties();

        final String nvdDataFeedUrl = settings.getString(Settings.KEYS.NVD_API_DATAFEED_URL);
        if (nvdDataFeedUrl != null) {
            return processDatafeed(nvdDataFeedUrl);
        }
        return processApi();
    }

    private boolean processDatafeed(String nvdDataFeedUrl) throws UpdateException {
        boolean updatesMade = false;
        try {
            dbProperties = cveDb.getDatabaseProperties();
            if (checkUpdate()) {
                FeedUrl urlData = FeedUrl.extractFromUrlOptionalPattern(nvdDataFeedUrl);
                final Properties cacheProperties = getRemoteDataFeedCacheProperties(urlData);
                urlData = urlData.withPattern(p -> p.orElse(cacheProperties.getProperty("prefix", FeedUrl.DEFAULT_FILE_PATTERN_PREFIX) + FeedUrl.DEFAULT_FILE_PATTERN_SUFFIX));

                final ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
                final SortedMap<String, String> updatable = getUpdatesNeeded(urlData, cacheProperties, now);
                if (!updatable.isEmpty()) {
                    final int downloadPoolSize = Math.min(
                            Runtime.getRuntime().availableProcessors(),
                            settings.getInt(Settings.KEYS.MAX_DOWNLOAD_THREAD_POOL_SIZE, 2)
                    );
                    // going over 2 threads does not appear to improve performance for the large data feed files
                    final int processingPoolSize = Math.min(DEFAULT_PROCESSING_THREAD_POOL_SIZE, 2);

                    ExecutorService downloadExecutorService = Executors.newFixedThreadPool(downloadPoolSize);
                    CancellableProcessorCompletions processorCompletions = new CancellableProcessorCompletions(Executors.newFixedThreadPool(processingPoolSize));
                    try {
                        CompletionService<NvdApiProcessor> downloadCompletions = scheduleAllDownloads(updatable, downloadExecutorService);

                        int awaitingProcessing = 0;
                        Optional<NvdApiProcessor> processLast = Optional.empty();

                        // Schedule processing as downloads complete, but delay the modified data until last if possible
                        for (int i = 0; i < updatable.size(); i++) {
                            NvdApiProcessor toBeProcessed = awaitNextCompletedDownload(downloadCompletions);

                            if (toBeProcessed.shouldProcessLast()) {
                                processLast = Optional.of(toBeProcessed);
                            } else {
                                awaitingProcessing++;
                                processorCompletions.submit(toBeProcessed);
                            }
                        }

                        // Wait for all processing to complete
                        for (int i = 0; i < awaitingProcessing; i++) {
                            awaitNextProcessedDownload(processorCompletions);
                        }

                        //download and process the modified as the last entry
                        if (processLast.isPresent()) {
                            processorCompletions.submit(processLast.get());
                            awaitNextProcessedDownload(processorCompletions);
                        }

                    } finally {
                        downloadExecutorService.shutdownNow();

                        // Cancel processors safely to avoid interrupting DB writes
                        processorCompletions.shutdown();

                        // Wait for them to complete, where
                        awaitTerminations(downloadExecutorService, "NVD datafeed download");
                        processorCompletions.awaitTerminations("NVD datafeed processing");
                    }
                    updatesMade = true;
                }
                storeLastModifiedDates(now, cacheProperties, updatable);
                if (updatesMade) {
                    cveDb.persistEcosystemCache();
                }
                final int updateCount = cveDb.updateEcosystemCache();
                LOGGER.debug("Corrected the ecosystem for {} ecoSystemCache entries", updateCount);
                if (updatesMade || updateCount > 0) {
                    cveDb.cleanupDatabase();
                }
            }
        } catch (DatabaseException ex) {
            throw new UpdateException("Database Exception, unable to update the data to use the most current data.", ex);
        }
        return updatesMade;
    }

    private void storeLastModifiedDates(final ZonedDateTime now, final Properties cacheProperties,
            final Map<String, String> updatable) {

        final ZonedDateTime lastModifiedRequest = DatabaseProperties.getTimestamp(cacheProperties,
                NVD_API_CACHE_MODIFIED_DATE + ".modified");
        dbProperties.save(DatabaseProperties.NVD_CACHE_LAST_CHECKED, now);
        dbProperties.save(DatabaseProperties.NVD_CACHE_LAST_MODIFIED, lastModifiedRequest);
        //allow users to initially load from a cache but then use the API - this may happen with the GH Action
        dbProperties.save(DatabaseProperties.NVD_API_LAST_CHECKED, now);
        dbProperties.save(DatabaseProperties.NVD_API_LAST_MODIFIED, lastModifiedRequest);

        for (String entry : updatable.keySet()) {
            final ZonedDateTime date = DatabaseProperties.getTimestamp(cacheProperties, NVD_API_CACHE_MODIFIED_DATE + "." + entry);
            dbProperties.save(DatabaseProperties.NVD_CACHE_LAST_MODIFIED + "." + entry, date);
        }
    }

    private CompletionService<NvdApiProcessor> scheduleAllDownloads(final SortedMap<String, String> updatable, ExecutorService downloadExecutorService) {
        final CompletionService<NvdApiProcessor> downloadCompletions = new ExecutorCompletionService<>(downloadExecutorService);
        for (Map.Entry<String, String> cve : updatable.entrySet()) {
            final DownloadTask call = new DownloadTask(cve.getValue(), cveDb, settings);
            downloadCompletions.submit(call);
        }
        return downloadCompletions;
    }

    private NvdApiProcessor awaitNextCompletedDownload(CompletionService<NvdApiProcessor> downloadCompletions) throws UpdateException {
        try {
            return downloadCompletions.take().get();
        } catch (InterruptedException ex) {
            LOGGER.debug("Thread was interrupted during download", ex);
            Thread.currentThread().interrupt();
            throw new UpdateException("The download was interrupted", ex);
        } catch (ExecutionException ex) {
            LOGGER.debug("Thread was interrupted during download execution", ex);
            throw new UpdateException("The execution of the download was interrupted", ex);
        }
    }

    private void awaitNextProcessedDownload(CancellableProcessorCompletions processorCompletions) throws UpdateException {
        try {
            processorCompletions.take();
        } catch (InterruptedException ex) {
            LOGGER.debug("Thread was interrupted during processing", ex);
            Thread.currentThread().interrupt();
            throw new UpdateException(ex);
        } catch (ExecutionException ex) {
            LOGGER.debug("Execution Exception during process", ex);
            throw new UpdateException(ex);
        }
    }

    private boolean processApi() throws UpdateException {
        final ZonedDateTime lastChecked = dbProperties.getTimestamp(DatabaseProperties.NVD_API_LAST_CHECKED);
        final int validForHours = settings.getInt(Settings.KEYS.NVD_API_VALID_FOR_HOURS, 0);
        if (cveDb.dataExists() && lastChecked != null && validForHours > 0) {
            // ms Valid = valid (hours) x 60 min/hour x 60 sec/min x 1000 ms/sec
            final long validForSeconds = validForHours * 60L * 60L;
            final ZonedDateTime now = ZonedDateTime.now(ZoneId.of("UTC"));
            final Duration duration = Duration.between(lastChecked, now);
            final long difference = duration.getSeconds();
            if (difference < validForSeconds) {
                LOGGER.info("Skipping the NVD API Update as it was completed within the last {} minutes", validForSeconds / 60);
                return false;
            }
        }

        ZonedDateTime lastModifiedRequest = dbProperties.getTimestamp(DatabaseProperties.NVD_API_LAST_MODIFIED);
        final NvdCveClientBuilder builder = NvdCveClientBuilder.aNvdCveApi();
        final String endpoint = settings.getString(Settings.KEYS.NVD_API_ENDPOINT);
        if (endpoint != null) {
            builder.withEndpoint(endpoint);
        }
        if (lastModifiedRequest != null) {
            // make it UTC as required by NvdCveClientBuilder#withLastModifiedFilter
            lastModifiedRequest = lastModifiedRequest.withZoneSameInstant(ZoneId.of("UTC"));
            final ZonedDateTime end = lastModifiedRequest.plusDays(120);
            builder.withLastModifiedFilter(lastModifiedRequest, end);
        }
        final String key = settings.getString(Settings.KEYS.NVD_API_KEY);
        if (StringUtils.isNotBlank(key)) {
            //using a higher delay as the system may not be able to process these faster.
            builder.withApiKey(key)
                    .withRequestsPerThirtySeconds(settings.getInt(Settings.KEYS.NVD_API_REQUESTS_PER_30_SECONDS_WITH_API_KEY, 50));
        } else {
            LOGGER.warn("An NVD API Key was not provided - it is highly recommended to use "
                    + "an NVD API key as the update can take a VERY long time without an API Key");
            builder.withRequestsPerThirtySeconds(settings.getInt(Settings.KEYS.NVD_API_REQUESTS_PER_30_SECONDS_WITHOUT_API_KEY, 5));
        }

        final int resultsPerPage = Math.min(settings.getInt(Settings.KEYS.NVD_API_RESULTS_PER_PAGE, RESULTS_PER_PAGE), RESULTS_PER_PAGE);

        builder.withResultsPerPage(resultsPerPage);
        //removed due to the virtualMatch filter causing overhead with the NVD API
        //final String virtualMatch = settings.getString(Settings.KEYS.CVE_CPE_STARTS_WITH_FILTER);
        //if (virtualMatch != null) {
        //    builder.withVirtualMatchString(virtualMatch);
        //}

        final int retryCount = settings.getInt(Settings.KEYS.NVD_API_MAX_RETRY_COUNT, 10);
        builder.withMaxRetryCount(retryCount);
        long delay = 0;
        try {
            delay = settings.getLong(Settings.KEYS.NVD_API_DELAY);
        } catch (InvalidSettingException ex) {
            LOGGER.warn("Invalid setting `NVD_API_DELAY`? ({}), using default delay", settings.getString(Settings.KEYS.NVD_API_DELAY));
        }
        if (delay > 0) {
            builder.withDelay(delay);
        }

        CancellableProcessorCompletions processorCompletions = new CancellableProcessorCompletions(Executors.newFixedThreadPool(DEFAULT_PROCESSING_THREAD_POOL_SIZE));
        try {
            int totalBatches = 0;
            try (NvdCveClient api = builder.build()) {
                int resultsAvailable = 0;
                while (api.hasNext()) {
                    final Collection<DefCveItem> items = api.next();
                    resultsAvailable = api.getTotalAvailable();
                    if (totalBatches == 0) {
                        LOGGER.info(String.format("NVD API has %,d records in this update", resultsAvailable));
                    }
                    if (items != null && !items.isEmpty()) {
                        final ObjectMapper objectMapper = new ObjectMapper();
                        objectMapper.registerModule(new JavaTimeModule());
                        final File outputFile = settings.getTempFile("nvd-data-", ".jsonarray.gz");
                        try (FileOutputStream fos = new FileOutputStream(outputFile); GZIPOutputStream out = new GZIPOutputStream(fos)) {
                            objectMapper.writeValue(out, items);
                            processorCompletions.submit(new NvdApiProcessor(cveDb, outputFile));
                        }
                        totalBatches += 1;
                        if ((totalBatches % 5) == 0) {
                            //TODO get results per page from the API as it could adjust automatically
                            final double percent = (double) (totalBatches * resultsPerPage) / resultsAvailable * 100;
                            if (percent < 100) {
                                LOGGER.info(String.format("Downloaded %,d/%,d (%.0f%%)", totalBatches * resultsPerPage, resultsAvailable, percent));
                            }
                        }
                    }
                    final ZonedDateTime last = api.getLastUpdated();
                    if (last != null && (lastModifiedRequest == null || lastModifiedRequest.compareTo(last) < 0)) {
                        lastModifiedRequest = last;
                    }
                }
                LOGGER.info(String.format("Downloaded %,d/%,d (%.0f%%)", resultsAvailable, resultsAvailable, 100f));

            } catch (Exception e) {
                if (e instanceof NvdApiException && e.getMessage().matches("NVD Returned Status Code: 40[34].*")) {
                    final String msg;
                    if (key != null) {
                        msg = "Error updating the NVD Data; the NVD returned a 403 or 404 error\n\nPlease ensure your API Key is valid; "
                                + "see https://github.com/jeremylong/open-vulnerability-cli/blob/main/README.md#api-key-is-used-and-a-403-or-404-error-occurs\n\n"
                                + "If your NVD API Key is valid try increasing the NVD API Delay.\n\n"
                                + "If this is occurring in a CI environment";
                    } else {
                        msg = "Error updating the NVD Data; the NVD returned a 403 or 404 error\n\nConsider using an NVD API Key; "
                                + "see https://github.com/dependency-check/DependencyCheck?tab=readme-ov-file#nvd-api-key-highly-recommended";
                    }
                    throw new UpdateException(msg, e);
                } else {
                    throw new UpdateException("Error updating the NVD Data", e);
                }
            }

            for (int processingBatch = 1; processingBatch <= totalBatches; processingBatch++) {
                try {
                    final NvdApiProcessor proc = processorCompletions.take();
                    final double percent = (double) processingBatch / totalBatches * 100;
                    LOGGER.info(String.format("Completed processing batch %d/%d (%.0f%%) in %,dms", processingBatch, totalBatches, percent, proc.getDurationMillis()));
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException(ex);
                } catch (ExecutionException ex) {
                    LOGGER.error("Exception processing NVD API Results", ex);
                    throw new RuntimeException(ex);
                }
            }
            if (lastModifiedRequest != null) {
                dbProperties.save(DatabaseProperties.NVD_API_LAST_CHECKED, ZonedDateTime.now());
                dbProperties.save(DatabaseProperties.NVD_API_LAST_MODIFIED, lastModifiedRequest);
            }
            return totalBatches > 0;
        } finally {
            processorCompletions.shutdown();
            processorCompletions.awaitTerminations("NVD API processing");
        }
    }

    private static void awaitTerminations(ExecutorService executorService, String taskDescription) {
        try {
            if (!executorService.awaitTermination(1, MINUTES)) {
                LOGGER.warn("Interrupted {} tasks did not complete safely within 1 minute; shutdown may be unsafe.", taskDescription);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Checks if the system is configured NOT to update.
     *
     * @return false if the system is configured to perform an update; otherwise
     * true
     */
    private boolean isUpdateConfiguredFalse() {
        if (!settings.getBoolean(Settings.KEYS.UPDATE_NVDCVE_ENABLED, true)) {
            return true;
        }
        boolean autoUpdate = true;
        try {
            autoUpdate = settings.getBoolean(Settings.KEYS.AUTO_UPDATE);
        } catch (InvalidSettingException ex) {
            LOGGER.debug("Invalid setting for auto-update; using true.");
        }
        return !autoUpdate;
    }

    @Override
    public boolean purge(Engine engine) {
        boolean result = true;
        try {
            final File dataDir = engine.getSettings().getDataDirectory();
            final File db = new File(dataDir, engine.getSettings().getString(Settings.KEYS.DB_FILE_NAME, "odc.mv.db"));
            if (db.exists()) {
                if (db.delete()) {
                    LOGGER.info("Database file purged; local copy of the NVD has been removed");
                } else {
                    LOGGER.error("Unable to delete '{}'; please delete the file manually", db.getAbsolutePath());
                    result = false;
                }
            } else {
                LOGGER.info("Unable to purge database; the database file does not exist: {}", db.getAbsolutePath());
                result = false;
            }
            final File traceFile = new File(dataDir, "odc.trace.db");
            if (traceFile.exists() && !traceFile.delete()) {
                LOGGER.error("Unable to delete '{}'; please delete the file manually", traceFile.getAbsolutePath());
                result = false;
            }
            final File lockFile = new File(dataDir, "odc.update.lock");
            if (lockFile.exists() && !lockFile.delete()) {
                LOGGER.error("Unable to delete '{}'; please delete the file manually", lockFile.getAbsolutePath());
                result = false;
            }
        } catch (IOException ex) {
            final String msg = "Unable to delete the database";
            LOGGER.error(msg, ex);
            result = false;
        }
        return result;
    }

    /**
     * Checks if the NVD API Cache JSON files were last checked recently. As an
     * optimization, we can avoid repetitive checks against the NVD cache.
     *
     * @return true to proceed with the check, or false to skip
     */
    private boolean checkUpdate() {
        boolean proceed = true;
        // If the valid setting has not been specified, then we proceed to check...
        final int validForHours = settings.getInt(Settings.KEYS.NVD_API_VALID_FOR_HOURS, 0);
        if (dataExists() && 0 < validForHours) {
            // ms Valid = valid (hours) x 60 min/hour x 60 sec/min x 1000 ms/sec
            final long validForSeconds = validForHours * 60L * 60L;
            final ZonedDateTime lastChecked = dbProperties.getTimestamp(DatabaseProperties.NVD_CACHE_LAST_CHECKED);
            if (lastChecked != null) {
                final ZonedDateTime now = ZonedDateTime.now(ZoneId.of("UTC"));
                final Duration duration = Duration.between(lastChecked, now);
                final long difference = duration.getSeconds();
                proceed = difference > validForSeconds;
                if (!proceed) {
                    LOGGER.info("Skipping NVD API Cache check since last check was within {} hours.", validForHours);
                    LOGGER.debug("Last NVD API was at {}, and now {} is within {} s.", lastChecked, now, validForSeconds);
                }
            } else {
                LOGGER.warn("NVD cache last checked not present; updating the entire database. This could occur if you are "
                        + "switching back and forth from using the API vs a datafeed or if you are using a database created prior to ODC 9.x");
            }
        }
        return proceed;
    }

    /**
     * Checks the CVE Index to ensure data exists and analysis can continue.
     *
     * @return true if the database contains data
     */
    private boolean dataExists() {
        return cveDb.dataExists();
    }

    /**
     * Determines if the index needs to be updated. This is done by fetching the
     * NVD CVE metadata and checking the last update date. If the data needs to
     * be refreshed this method will return the NvdCveUrl for the files that
     * need to be updated.
     *
     * @param feedUrl a parsed NVD cache / data feed URL
     * @param cacheProperties the properties from the remote NVD API cache or data feed
     * @param now the start time of the update process
     * @return the map of key to URLs - where the key is the year or `modified`
     */
    protected final SortedMap<String, String> getUpdatesNeeded(FeedUrl feedUrl, Properties cacheProperties, ZonedDateTime now) {
        LOGGER.debug("starting getUpdatesNeeded() ...");
        final SortedMap<String, String> updates = new TreeMap<>();
        if (dbProperties != null && !dbProperties.isEmpty()) {
            Pair<Integer, Integer> yearRange = FeedUrl.toYearRange(settings, now);
            int startYear = yearRange.getLeft();
            int endYear = yearRange.getRight();
            boolean needsFullUpdate = false;
            for (int y = startYear; y <= endYear; y++) {
                final ZonedDateTime val = dbProperties.getTimestamp(DatabaseProperties.NVD_CACHE_LAST_MODIFIED + "." + y);
                if (val == null && FeedUrl.isMandatoryFeedYear(now, y)) {
                    needsFullUpdate = true;
                    break;
                }
            }
            final ZonedDateTime lastUpdated = dbProperties.getTimestamp(DatabaseProperties.NVD_CACHE_LAST_MODIFIED);
            final int days = settings.getInt(Settings.KEYS.NVD_API_DATAFEED_VALID_FOR_DAYS, 7);

            if (!needsFullUpdate && lastUpdated.equals(DatabaseProperties.getTimestamp(cacheProperties, NVD_API_CACHE_MODIFIED_DATE))) {
                return updates;
            } else {
                updates.put("modified", feedUrl.toFormattedUrlString("modified"));
                if (needsFullUpdate) {
                    for (int i = startYear; i <= endYear; i++) {
                        if (cacheProperties.containsKey(NVD_API_CACHE_MODIFIED_DATE + "." + i)) {
                            updates.put(String.valueOf(i), feedUrl.toFormattedUrlString(i));
                        }
                    }
                } else if (!DateUtil.withinDateRange(lastUpdated, now, days)) {
                    for (int i = startYear; i <= endYear; i++) {
                        if (cacheProperties.containsKey(NVD_API_CACHE_MODIFIED_DATE + "." + i)) {
                            final ZonedDateTime lastModifiedCache = DatabaseProperties.getTimestamp(cacheProperties,
                                    NVD_API_CACHE_MODIFIED_DATE + "." + i);
                            final ZonedDateTime lastModifiedDB = dbProperties.getTimestamp(DatabaseProperties.NVD_CACHE_LAST_MODIFIED + "." + i);
                            if (lastModifiedDB == null || (lastModifiedCache != null && lastModifiedCache.compareTo(lastModifiedDB) > 0)) {
                                updates.put(String.valueOf(i), feedUrl.toFormattedUrlString(i));
                            }
                        }
                    }
                }
            }
        }
        if (updates.size() > 3) {
            LOGGER.info("NVD API Cache / Data Feed requires several updates; this could take a couple of minutes.");
        }
        return updates;
    }

    /**
     * Downloads the metadata properties of the NVD API cache / data feed.
     *
     * @param dataFeedUrl a parsed NVD cache / data feed URL
     * @return the cache properties
     * @throws UpdateException thrown if the properties file could not be downloaded
     */
    protected final Properties getRemoteDataFeedCacheProperties(FeedUrl dataFeedUrl) throws UpdateException {
        try {
            final Properties properties = new Properties();
            final String content = Downloader.getInstance().fetchContent(dataFeedUrl.toSuffixedUrl("cache.properties"), UTF_8);
            properties.load(new StringReader(content));
            return properties;

        } catch (DownloadFailedException | ResourceNotFoundException ex) {
            LOGGER.debug("Unable to download the NVD API cache.properties due to [{}]; attempting to build from data feed metadata files instead...", ex.toString());
            return generateRemoteDataFeedCachePropertiesFromMetadata(dataFeedUrl);
        } catch (URISyntaxException | MalformedURLException ex) {
            throw new UpdateException("Invalid NVD Cache / Data Feed URL", ex);
        } catch (TooManyRequestsException ex) {
            throw new UpdateException("Unable to download the NVD API cache.properties", ex);
        } catch (IOException ex) {
            throw new UpdateException("Invalid NVD Cache properties file contents", ex);
        }
    }

    /**
     * Builds the metadata properties from individual metadata fields within the data feed
     *
     * @param dataFeedUrl a parsed NVD cache / data feed URL
     * @return the cache properties
     * @throws UpdateException thrown if the metadata files could not be downloaded to build cache properties
     */
    private Properties generateRemoteDataFeedCachePropertiesFromMetadata(FeedUrl dataFeedUrl) throws UpdateException {
        FeedUrl metaFeedUrl = dataFeedUrl.withPattern(p -> p
                .orElse(FeedUrl.DEFAULT_FILE_PATTERN)
                .replace(".json.gz", ".meta")
        );

        final Properties properties = new Properties();
        ZonedDateTime lmd = metaFeedUrl.getLastModifiedFor("modified");
        DatabaseProperties.setTimestamp(properties, NVD_API_CACHE_MODIFIED_DATE + ".modified", lmd);
        DatabaseProperties.setTimestamp(properties, NVD_API_CACHE_MODIFIED_DATE, lmd);

        metaFeedUrl.getLastModifiedDatePropertiesByYear(this.settings, ZonedDateTime.now(ZoneOffset.UTC))
                .forEach((k, v) -> DatabaseProperties.setTimestamp(properties, k, v));
        return properties;
    }

    protected static class FeedUrl {

        /**
         * Default file pattern prefix for NVD caches; generally those generated by vulnz / Open Vulnerability Clients
         */
        static final String DEFAULT_FILE_PATTERN_PREFIX = "nvdcve-";
        /**
         * Default file pattern suffix for NVD caches; generally those generated by vulnz / Open Vulnerability Clients
         */
        static final String DEFAULT_FILE_PATTERN_SUFFIX = "{0}.json.gz";
        /**
         * Default file pattern for NVD caches; generally those generated by vulnz / Open Vulnerability Clients
         */
        static final String DEFAULT_FILE_PATTERN = DEFAULT_FILE_PATTERN_PREFIX + DEFAULT_FILE_PATTERN_SUFFIX;

        /**
         * The timezone where the new year starts first.
         */
        static final ZoneId ZONE_GLOBAL_EARLIEST = ZoneId.of("UTC+14:00");
        /**
         * The timezone where the new year starts last.
         */
        static final ZoneId ZONE_GLOBAL_LATEST = ZoneId.of("UTC-12:00");

        /**
         * The base URL to download resources from.
         */
        private final String url;

        /**
         * The pattern to construct the file names for resources from.
         */
        private final String pattern;

        public FeedUrl(String url, String pattern) {
            this.url = url;
            this.pattern = pattern;
        }

        public FeedUrl withPattern(Function<Optional<String>, String> patternTransformer) {
            return new FeedUrl(url, patternTransformer.apply(Optional.ofNullable(pattern)));
        }

        @NonNull String toFormattedUrlString(String formatArg) {
            return url + MessageFormat.format(Optional.ofNullable(pattern).orElseThrow(), formatArg);
        }

        @NonNull String toFormattedUrlString(int formatArg) {
            return toFormattedUrlString(String.valueOf(formatArg));
        }

        @NonNull URL toFormattedUrl(@NonNull String formatArg) throws MalformedURLException, URISyntaxException {
            return new URI(toFormattedUrlString(formatArg)).toURL();
        }

        @SuppressWarnings("SameParameterValue")
        @NonNull URL toSuffixedUrl(String suffix) throws MalformedURLException, URISyntaxException {
            return new URI(url + suffix).toURL();
        }

        /**
         * @param url A NVD data feed URL which may be just a base URL such as https://my-nvd-cache/nvd_cache or
         *            may include a formatted URL ending with .json.gz such as https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{0}.json.gz
         * @return A constructed FeedUrl object
         */
        @SuppressWarnings("JavadocLinkAsPlainText")
        protected static FeedUrl extractFromUrlOptionalPattern(String url) {
            String baseUrl;
            String pattern = null;
            if (url.endsWith(".json.gz")) {
                final int lio = url.lastIndexOf("/");
                pattern = url.substring(lio + 1);
                baseUrl = url.substring(0, lio);
            } else {
                baseUrl = url;
            }
            if (!baseUrl.endsWith("/")) {
                baseUrl += "/";
            }
            return new FeedUrl(baseUrl, pattern);
        }

        private static @NonNull Pair<Integer, Integer> toYearRange(Settings settings, ZonedDateTime now) {
            // for establishing the current year use the timezone where the new year starts first
            // as from that moment on CNAs might start assigning CVEs with the new year depending
            // on the CNA's timezone
            final int startYear = settings.getInt(Settings.KEYS.NVD_API_DATAFEED_START_YEAR, 2002);
            final int endYear = now.withZoneSameInstant(ZONE_GLOBAL_EARLIEST).getYear();
            return new Pair<>(startYear, endYear);
        }

        private @NonNull ZonedDateTime getLastModifiedFor(int year) throws UpdateException {
            return getLastModifiedFor(String.valueOf(year));
        }

        private @NonNull ZonedDateTime getLastModifiedFor(String fileVersion) throws UpdateException {
            try {
                String content = Downloader.getInstance().fetchContent(toFormattedUrl(fileVersion), UTF_8);
                Properties props = new Properties();
                props.load(new StringReader(content));
                return Objects.requireNonNull(DatabaseProperties.getIsoTimestamp(props, NVD_API_CACHE_MODIFIED_DATE));
            } catch (Exception ex) {
                throw new UpdateException("Unable to download & parse the data feed .meta file for " + fileVersion, ex);
            }
        }

        Map<String, ZonedDateTime> getLastModifiedDatePropertiesByYear(Settings settings, ZonedDateTime now) throws UpdateException {
            Pair<Integer, Integer> yearRange = toYearRange(settings, now);
            Map<String, ZonedDateTime> lastModifiedDateProperties = new LinkedHashMap<>();
            for (int y = yearRange.getLeft(); y <= yearRange.getRight(); y++) {
                try {
                    lastModifiedDateProperties.put(NVD_API_CACHE_MODIFIED_DATE + "." + y, getLastModifiedFor(y));
                } catch (UpdateException e) {
                    if (isMandatoryFeedYear(now, y)) {
                        throw e;
                    }
                    LOGGER.debug("Ignoring data feed metadata retrieval failure for {}, it is still January 1st in some TZ; so feed files may not yet be generated. Error was {}", y, e.toString());
                }
            }
            return lastModifiedDateProperties;
        }

        /**
         * @param now        The current time in any timezone
         * @param targetYear Target year's feed data to retrieve
         * @return Whether or not the targetYear is considered a mandatory feed file to retrieve given the target year and current time.
         */
        static boolean isMandatoryFeedYear(ZonedDateTime now, int targetYear) {
            return isNotTargetYearInAnyTZ(now, targetYear) || isAfterJanuary1InEveryTZ(now, targetYear);
        }

        private static boolean isNotTargetYearInAnyTZ(ZonedDateTime now, int targetYear) {
            return targetYear != now.withZoneSameInstant(ZONE_GLOBAL_EARLIEST).getYear();
        }

        private static boolean isAfterJanuary1InEveryTZ(ZonedDateTime now, int targetYear) {
            return now.isAfter(LocalDate.of(targetYear, 1, 2).atStartOfDay().atZone(ZONE_GLOBAL_LATEST));
        }
    }

    private static class CancellableProcessorCompletions {
        private final Set<NvdApiProcessor> tasks = Collections.newSetFromMap(new IdentityHashMap<>());
        private final ExecutorService executorService;
        private final CompletionService<NvdApiProcessor> completions;

        public CancellableProcessorCompletions(ExecutorService executorService) {
            this.executorService = executorService;
            this.completions = new ExecutorCompletionService<>(this.executorService);
        }

        public void submit(@NonNull NvdApiProcessor task) {
            tasks.add(task);
            completions.submit(task);
        }

        public NvdApiProcessor take() throws InterruptedException, ExecutionException {
            NvdApiProcessor result = completions.take().get();
            tasks.remove(result);
            return result;
        }

        /**
         * Shuts down NvdApiProcessor tasks safely without thread interruption; to avoid causing accidental
         * premature database closure.
         */
        public void shutdown() {
            tasks.forEach(NvdApiProcessor::cancel);
            tasks.clear();
            executorService.shutdown();
        }

        public void awaitTerminations(String taskDescription) {
            NvdApiDataSource.awaitTerminations(executorService, taskDescription);
        }
    }
}
