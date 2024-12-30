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
package org.owasp.dependencycheck.data.update.nvd.api;

import java.io.File;
import java.net.URL;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A callable object to download the NVD API cache files and start the
 * NvdApiProcessor.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class DownloadTask implements Callable<Future<NvdApiProcessor>> {

    /**
     * The Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DownloadTask.class);
    /**
     * The CVE DB to use when processing the files.
     */
    private final CveDB cveDB;
    /**
     * The processor service to pass the results of the download to.
     */
    private final ExecutorService processorService;
    /**
     * The NVD API Cache file URL.
     */
    private final String url;
    /**
     * A reference to the global settings object.
     */
    private final Settings settings;

    /**
     * Simple constructor for the callable download task.
     *
     * @param url the file to download
     * @param processor the processor service to submit the downloaded files to
     * @param cveDB the CVE DB to use to store the vulnerability data
     * @param settings a reference to the global settings object; this is
     * necessary so that when the thread is started the dependencies have a
     * correct reference to the global settings.
     */
    public DownloadTask(String url, ExecutorService processor, CveDB cveDB, Settings settings) {
        this.url = url;
        this.processorService = processor;
        this.cveDB = cveDB;
        this.settings = settings;
    }

    @SuppressWarnings("BusyWait")
    @Override
    public Future<NvdApiProcessor> call() throws Exception {
        try {
            final URL u = new URL(url);
            LOGGER.info("Download Started for NVD Cache - {}", url);
            final long startDownload = System.currentTimeMillis();
            final File outputFile = settings.getTempFile("nvd-datafeed-", "json.gz");
            Downloader.getInstance().fetchFile(u, outputFile, true, Settings.KEYS.NVD_API_DATAFEED_USER, Settings.KEYS.NVD_API_DATAFEED_PASSWORD,
                    Settings.KEYS.NVD_API_DATAFEED_BEARER_TOKEN);
            if (this.processorService == null) {
                return null;
            }
            final NvdApiProcessor task = new NvdApiProcessor(cveDB, outputFile, startDownload);
            final Future<NvdApiProcessor> val = this.processorService.submit(task);
            return val;
        } catch (Throwable ex) {
            LOGGER.error("Error downloading NVD CVE - {} Reason: {}", url, ex.getMessage());
            throw ex;
        } finally {
            settings.cleanup(false);
        }
    }

    /**
     * Returns true if the process task is for the modified json file from the
     * NVD API Cache.
     *
     * @return <code>true</code> if the process task is for the modified data;
     * otherwise <code>false</code>
     */
    public boolean isModified() {
        return StringUtils.containsIgnoreCase(url, "modified");
    }
}
