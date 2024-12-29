/*
 * This file is part of dependency-check-ant.
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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.taskdefs;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.jetbrains.annotations.Nullable;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.impl.StaticLoggerBinder;

/**
 * An Ant task definition to execute dependency-check update. This will download
 * the latest data from the National Vulnerability Database (NVD) and store a
 * copy in the local database.
 *
 * @author Jeremy Long
 */
//While duplicate code is general bad - this is calling out getters/setters
//on unrelated ODC clients (the DependencyCheckScanAgent).
@SuppressWarnings("common-java:DuplicatedBlocks")
public class Update extends Purge {

    /**
     * The URL to (a mirror of) the RetireJS JSON data.
     */
    private String retireJsUrl;
    /**
     * The user to download the RetireJS JSON data from an HTTP Basic auth protected location.
     */
    private String retireJsUrlUser;
    /**
     * The password to download the RetireJS JSON data from an HTTP Basic auth protected location.
     */
    private String retireJsUrlPassword;
    /**
     * The token to download the RetireJS JSON data from an HTTP Bearer auth protected location.
     */
    private String retireJsUrlBearerToken;
    /**
     * Whether or not the RetireJS JSON repository will be updated regardless of the
     * `autoupdate` settings. Defaults to false.
     */
    private Boolean retireJsForceUpdate;
    /**
     * Whether or not the Known Exploited Vulnerability Analyzer is enabled.
     */
    private Boolean knownExploitedEnabled;
    /**
     * The URL to the known exploited vulnerabilities JSON datafeed.
     */
    private String knownExploitedUrl;
    /**
     * The number of hours before checking for updates for the known exploited vulnerabilities JSON datafeed.
     */
    private Integer knownExploitedValidForHours;
    /**
     * The user to download the known exploited vulnerabilities JSON datafeed from an HTTP Basic auth protected location.
     */
    private String knownExploitedUser;
    /**
     * The password to download the known exploited vulnerabilities JSON datafeed from an HTTP Basic auth protected location.
     */
    private String knownExploitedPassword;
    /**
     * The token to download the known exploited vulnerabilities JSON datafeed from an HTTP Bearer auth protected location.
     */
    private String knownExploitedBearerToken;
    /**
     * The NVD API endpoint.
     */
    private String nvdApiEndpoint;
    /**
     * The NVD API Key.
     */
    private String nvdApiKey;
    /**
     * The maximum number of retry requests for a single call to the NVD API.
     */
    private Integer nvdMaxRetryCount;
    /**
     * The number of hours to wait before checking for new updates from the NVD.
     */
    private Integer nvdValidForHours;
    /**
     * The NVD API Data Feed URL.
     */
    private String nvdDatafeedUrl;
    /**
     * The username to download the NVD Data feed from an HTTP Basic auth protected location.
     */
    private String nvdUser;
    /**
     * The password to download the NVD Data feed from an HTTP Basic auth protected location.
     */
    private String nvdPassword;
    /**
     * The token to download the NVD Data feed from an HTTP Bearer auth protected location.
     */
    private String nvdBearerToken;
    /**
     * The time in milliseconds to wait between downloading NVD API data.
     */
    private Integer nvdApiDelay;

    /**
     * The number of records per page of NVD API data.
     */
    private Integer nvdApiResultsPerPage;

    /**
     * The Proxy Server.
     */
    private String proxyServer;
    /**
     * The Proxy Port.
     */
    private String proxyPort;
    /**
     * The Proxy username.
     */
    private String proxyUsername;
    /**
     * The Proxy password.
     */
    private String proxyPassword;
    /**
     * Non proxy hosts
     */
    private String nonProxyHosts;
    /**
     * The Connection Timeout.
     */
    private String connectionTimeout;
    /**
     * The Read Timeout.
     */
    private String readTimeout;
    /**
     * The database driver name; such as org.h2.Driver.
     */
    private String databaseDriverName;
    /**
     * The path to the database driver JAR file if it is not on the class path.
     */
    private String databaseDriverPath;
    /**
     * The database connection string.
     */
    private String connectionString;
    /**
     * The user name for connecting to the database.
     */
    private String databaseUser;
    /**
     * The password to use when connecting to the database.
     */
    private String databasePassword;
    /**
     * The number of hours to wait before re-checking hosted suppressions file
     * for updates.
     */
    private Integer hostedSuppressionsValidForHours;
    /**
     * The userid for the hostedSuppressions file.
     * <br/>
     * Only needs configuration if you customized the hostedSuppressionsUrl to a custom server that requires Basic Auth
     */
    private String hostedSuppressionsUser;
    /**
     * The password for the hostedSuppressions file.
     * <br/>
     * Only needs configuration if you customized the hostedSuppressionsUrl to a custom server that requires Basic Auth
     */
    private String hostedSuppressionsPassword;
    /**
     * The (Bearer authentication) API Token for the hostedSuppressions file.
     * <br/>
     * Only needs configuration if you customized the hostedSuppressionsUrl to a custom server that requires Bearer Auth
     */
    private String hostedSuppressionsBearerToken;
    /**
     * Whether the hosted suppressions file will be updated regardless of the
     * `autoupdate` settings. Defaults to false.
     */
    private Boolean hostedSuppressionsForceUpdate;
    /**
     * Whether the hosted suppressions file will be used. Defaults to true.
     */
    private Boolean hostedSuppressionsEnabled;
    /**
     * The URL to hosted suppressions file with base FP suppressions.
     */
    private String hostedSuppressionsUrl = null;
    /**
     * Whether or not the RetireJS Analyzer is enabled.
     */
    private Boolean retireJsAnalyzerEnabled;

    /**
     * Construct a new UpdateTask.
     */
    public Update() {
        super();
        // Call this before Dependency Check Core starts logging anything - this way, all SLF4J messages from
        // core end up coming through this tasks logger
        StaticLoggerBinder.getSingleton().setTask(this);
    }

    /**
     * Set the value of nvdApiEndpoint.
     *
     * @param nvdApiEndpoint new value of nvdApiEndpoint
     */
    public void setNvdApiEndpoint(String nvdApiEndpoint) {
        this.nvdApiEndpoint = nvdApiEndpoint;
    }

    /**
     * Set the value of nvdApiKey.
     *
     * @param nvdApiKey new value of nvdApiKey
     */
    public void setNvdApiKey(String nvdApiKey) {
        this.nvdApiKey = nvdApiKey;
    }

    /**
     * Set the value of nvdMaxRetryCount.
     *
     * @param nvdMaxRetryCount new value of nvdMaxRetryCount
     */
    public void setNvdMaxRetryCount(Integer nvdMaxRetryCount) {
        if (nvdMaxRetryCount > 0) {
            this.nvdMaxRetryCount = nvdMaxRetryCount;
        } else {
            throw new BuildException("Invalid setting: `nvdMaxRetryCount` must be greater than zero");
        }
    }

    /**
     * Set the value of nvdValidForHours.
     *
     * @param nvdValidForHours new value of nvdValidForHours
     */
    public void setNvdValidForHours(int nvdValidForHours) {
        if (nvdValidForHours >= 0) {
            this.nvdValidForHours = nvdValidForHours;
        } else {
            throw new BuildException("Invalid setting: `nvdValidForHours` must be 0 or greater");
        }
    }

    /**
     * Set the value of nvdDatafeedUrl.
     *
     * @param nvdDatafeedUrl new value of nvdDatafeedUrl
     */
    public void setNvdDatafeedUrl(String nvdDatafeedUrl) {
        this.nvdDatafeedUrl = nvdDatafeedUrl;
    }

    /**
     * Set the value of nvdUser.
     *
     * @param nvdUser new value of nvdUser
     */
    public void setNvdUser(String nvdUser) {
        this.nvdUser = nvdUser;
    }

    /**
     * Set the value of nvdPassword.
     *
     * @param nvdPassword new value of nvdPassword
     */
    public void setNvdPassword(String nvdPassword) {
        this.nvdPassword = nvdPassword;
    }

    /**
     * Sets the token to download the NVD Data feed from an HTTP Bearer auth protected location.
     * @param nvdBearerToken The bearer token
     */
    public void setNvdBearerToken(String nvdBearerToken) {
        this.nvdBearerToken = nvdBearerToken;
    }

    /**
     * Set the value of nvdApiDelay.
     *
     * @param nvdApiDelay new value of nvdApiDelay
     */
    public void setNvdApiDelay(Integer nvdApiDelay) {
        this.nvdApiDelay = nvdApiDelay;
    }

    /**
     * Set the value of nvdApiResultsPerPage.
     *
     * @param nvdApiResultsPerPage new value of nvdApiResultsPerPage
     */
    public void setNvdApiResultsPerPage(Integer nvdApiResultsPerPage) {
        this.nvdApiResultsPerPage = nvdApiResultsPerPage;
    }

    /**
     * Set the value of proxyServer.
     *
     * @param server new value of proxyServer
     */
    public void setProxyServer(String server) {
        this.proxyServer = server;
    }

    /**
     * Set the value of proxyPort.
     *
     * @param proxyPort new value of proxyPort
     */
    public void setProxyPort(String proxyPort) {
        this.proxyPort = proxyPort;
    }

    /**
     * Set the value of proxyUsername.
     *
     * @param proxyUsername new value of proxyUsername
     */
    public void setProxyUsername(String proxyUsername) {
        this.proxyUsername = proxyUsername;
    }

    /**
     * Set the value of proxyPassword.
     *
     * @param proxyPassword new value of proxyPassword
     */
    public void setProxyPassword(String proxyPassword) {
        this.proxyPassword = proxyPassword;
    }

    /**
     * Set the value of nonProxyHosts.
     *
     * @param nonProxyHosts new value of nonProxyHosts
     */
    public void setNonProxyHosts(String nonProxyHosts) {
        this.nonProxyHosts = nonProxyHosts;
    }

    /**
     * Set the value of connectionTimeout.
     *
     * @param connectionTimeout new value of connectionTimeout
     */
    public void setConnectionTimeout(String connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    /**
     * Set the value of readTimeout.
     *
     * @param readTimeout new value of readTimeout
     */
    public void setReadTimeout(String readTimeout) {
        this.readTimeout = readTimeout;
    }

    /**
     * Set the value of databaseDriverName.
     *
     * @param databaseDriverName new value of databaseDriverName
     */
    public void setDatabaseDriverName(String databaseDriverName) {
        this.databaseDriverName = databaseDriverName;
    }

    /**
     * Set the value of databaseDriverPath.
     *
     * @param databaseDriverPath new value of databaseDriverPath
     */
    public void setDatabaseDriverPath(String databaseDriverPath) {
        this.databaseDriverPath = databaseDriverPath;
    }

    /**
     * Set the value of connectionString.
     *
     * @param connectionString new value of connectionString
     */
    public void setConnectionString(String connectionString) {
        this.connectionString = connectionString;
    }

    /**
     * Set the value of databaseUser.
     *
     * @param databaseUser new value of databaseUser
     */
    public void setDatabaseUser(String databaseUser) {
        this.databaseUser = databaseUser;
    }

    /**
     * Set the value of databasePassword.
     *
     * @param databasePassword new value of databasePassword
     */
    public void setDatabasePassword(String databasePassword) {
        this.databasePassword = databasePassword;
    }

    /**
     * Set the value of hostedSuppressionsValidForHours.
     *
     * @param hostedSuppressionsValidForHours new value of
     * hostedSuppressionsValidForHours
     */
    public void setHostedSuppressionsValidForHours(final Integer hostedSuppressionsValidForHours) {
        this.hostedSuppressionsValidForHours = hostedSuppressionsValidForHours;
    }

    public void setHostedSuppressionsUser(String hostedSuppressionsUser) {
        this.hostedSuppressionsUser = hostedSuppressionsUser;
    }

    public void setHostedSuppressionsPassword(String hostedSuppressionsPassword) {
        this.hostedSuppressionsPassword = hostedSuppressionsPassword;
    }

    public void setHostedSuppressionsBearerToken(String hostedSuppressionsBearerToken) {
        this.hostedSuppressionsBearerToken = hostedSuppressionsBearerToken;
    }

    /**
     * Set the value of hostedSuppressionsForceUpdate.
     *
     * @param hostedSuppressionsForceUpdate new value of
     * hostedSuppressionsForceUpdate
     */
    public void setHostedSuppressionsForceUpdate(final Boolean hostedSuppressionsForceUpdate) {
        this.hostedSuppressionsForceUpdate = hostedSuppressionsForceUpdate;
    }

    /**
     * Set the value of hostedSuppressionsEnabled.
     *
     * @param hostedSuppressionsEnabled new value of hostedSuppressionsEnabled
     */
    public void setHostedSuppressionsEnabled(Boolean hostedSuppressionsEnabled) {
        this.hostedSuppressionsEnabled = hostedSuppressionsEnabled;
    }

    /**
     * Set the value of hostedSuppressionsUrl.
     *
     * @param hostedSuppressionsUrl new value of hostedSuppressionsUrl
     */
    public void setHostedSuppressionsUrl(final String hostedSuppressionsUrl) {
        this.hostedSuppressionsUrl = hostedSuppressionsUrl;
    }

    /**
     * Sets the the knownExploitedUrl.
     *
     * @param knownExploitedUrl the URL
     */
    public void setKnownExploitedUrl(String knownExploitedUrl) {
        this.knownExploitedUrl = knownExploitedUrl;
    }

    public void setKnownExploitedValidForHours(Integer knownExploitedValidForHours) {
        this.knownExploitedValidForHours = knownExploitedValidForHours;
    }

    /**
     * Sets the user for downloading the knownExploitedUrl from a HTTP Basic auth protected location.
     *
     * @param knownExploitedUser the user
     */
    public void setKnownExploitedUser(String knownExploitedUser) {
        this.knownExploitedUser = knownExploitedUser;
    }

    /**
     * Sets the password for downloading the knownExploitedUrl from a HTTP Basic auth protected location..
     *
     * @param knownExploitedPassword the password
     */
    public void setKnownExploitedPassword(String knownExploitedPassword) {
        this.knownExploitedPassword = knownExploitedPassword;
    }

    /**
     * Sets the token for downloading the knownExploitedUrl from an HTTP Bearer auth protected location..
     *
     * @param knownExploitedBearerToken the token
     */
    public void setKnownExploitedBearerToken(String knownExploitedBearerToken) {
        this.knownExploitedBearerToken = knownExploitedBearerToken;
    }

    /**
     * Sets whether the analyzer is enabled.
     *
     * @param knownExploitedEnabled the value of the new setting
     */
    public void setKnownExploitedEnabled(Boolean knownExploitedEnabled) {
        this.knownExploitedEnabled = knownExploitedEnabled;
    }

    /**
     * Set the value of the Retire JS repository URL.
     *
     * @param retireJsUrl new value of retireJsUrl
     */
    public void setRetireJsUrl(String retireJsUrl) {
        this.retireJsUrl = retireJsUrl;
    }

    /**
     * Sets the user to download the RetireJS JSON data from an HTTP Basic auth protected location.
     *
     * @param retireJsUrlUser new value of retireJsUrlUser
     */
    public void setRetireJsUrlUser(String retireJsUrlUser) {
        this.retireJsUrlUser = retireJsUrlUser;
    }

    /**
     * Sets the password to download the RetireJS JSON data from an HTTP Basic auth protected location.
     *
     * @param retireJsUrlPassword new value of retireJsUrlPassword
     */
    public void setRetireJsUrlPassword(String retireJsUrlPassword) {
        this.retireJsUrlPassword = retireJsUrlPassword;
    }

    /**
     * Sets the token to download the RetireJS JSON data from an HTTP Bearer auth protected location.
     *
     * @param retireJsUrlBearerToken new value of retireJsUrlBearerToken
     */
    public void setRetireJsUrlBearerToken(String retireJsUrlBearerToken) {
        this.retireJsUrlBearerToken = retireJsUrlBearerToken;
    }

    /**
     * Set the value of retireJsForceUpdate.
     *
     * @param retireJsForceUpdate new value of
     * retireJsForceUpdate
     */
    public void setRetireJsForceUpdate(Boolean retireJsForceUpdate) {
        this.retireJsForceUpdate = retireJsForceUpdate;
    }

    /**
     * Set the value of retireJsAnalyzerEnabled.
     *
     * @param retireJsAnalyzerEnabled new value of retireJsAnalyzerEnabled
     */
    public void setRetireJsAnalyzerEnabled(Boolean retireJsAnalyzerEnabled) {
        this.retireJsAnalyzerEnabled = retireJsAnalyzerEnabled;
    }

    /**
     * Executes the update by initializing the settings, downloads the NVD XML
     * data, and then processes the data storing it in the local database.
     *
     * @throws BuildException thrown if a connection to the local database
     * cannot be made.
     */
    //see note on `Check.dealWithReferences()` for information on this suppression
    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    @Override
    protected void executeWithContextClassloader() throws BuildException {
        populateSettings();
        try {
            Downloader.getInstance().configure(getSettings());
        } catch (InvalidSettingException e) {
            throw new BuildException(e);
        }
        try (Engine engine = new Engine(Update.class.getClassLoader(), getSettings())) {
            engine.doUpdates();
        } catch (UpdateException ex) {
            if (this.isFailOnError()) {
                throw new BuildException(ex);
            }
            log(ex.getMessage(), Project.MSG_ERR);
        } catch (DatabaseException ex) {
            final String msg = "Unable to connect to the dependency-check database; unable to update the NVD data";
            if (this.isFailOnError()) {
                throw new BuildException(msg, ex);
            }
            log(msg, Project.MSG_ERR);
        } finally {
            getSettings().cleanup();
        }
    }

    /**
     * Takes the properties supplied and updates the dependency-check settings.
     * Additionally, this sets the system properties required to change the
     * proxy server, port, and connection timeout.
     *
     * @throws BuildException thrown when an invalid setting is configured.
     */
    //see note on `Check.dealWithReferences()` for information on this suppression
    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    @Override
    protected void populateSettings() throws BuildException {
        super.populateSettings();
        getSettings().setStringIfNotEmpty(Settings.KEYS.PROXY_SERVER, proxyServer);
        getSettings().setStringIfNotEmpty(Settings.KEYS.PROXY_PORT, proxyPort);
        getSettings().setStringIfNotEmpty(Settings.KEYS.PROXY_USERNAME, proxyUsername);
        getSettings().setStringIfNotEmpty(Settings.KEYS.PROXY_PASSWORD, proxyPassword);
        getSettings().setStringIfNotEmpty(Settings.KEYS.PROXY_NON_PROXY_HOSTS, nonProxyHosts);
        getSettings().setStringIfNotEmpty(Settings.KEYS.CONNECTION_TIMEOUT, connectionTimeout);
        getSettings().setStringIfNotEmpty(Settings.KEYS.CONNECTION_READ_TIMEOUT, readTimeout);
        getSettings().setStringIfNotEmpty(Settings.KEYS.DB_DRIVER_NAME, databaseDriverName);
        getSettings().setStringIfNotEmpty(Settings.KEYS.DB_DRIVER_PATH, databaseDriverPath);
        getSettings().setStringIfNotEmpty(Settings.KEYS.DB_CONNECTION_STRING, connectionString);
        getSettings().setStringIfNotEmpty(Settings.KEYS.DB_USER, databaseUser);
        getSettings().setStringIfNotEmpty(Settings.KEYS.DB_PASSWORD, databasePassword);

        getSettings().setStringIfNotEmpty(Settings.KEYS.KEV_URL, knownExploitedUrl);
        getSettings().setStringIfNotEmpty(Settings.KEYS.KEV_USER, knownExploitedUser);
        getSettings().setStringIfNotEmpty(Settings.KEYS.KEV_PASSWORD, knownExploitedPassword);
        getSettings().setStringIfNotEmpty(Settings.KEYS.KEV_BEARER_TOKEN, knownExploitedBearerToken);
        getSettings().setIntIfNotNull(Settings.KEYS.KEV_CHECK_VALID_FOR_HOURS, knownExploitedValidForHours);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_KNOWN_EXPLOITED_ENABLED, knownExploitedEnabled);

        getSettings().setStringIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, retireJsUrl);
        getSettings().setStringIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_USER, retireJsUrlUser);
        getSettings().setStringIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_PASSWORD, retireJsUrlPassword);
        getSettings().setStringIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_BEARER_TOKEN, retireJsUrlBearerToken);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_FORCEUPDATE, retireJsForceUpdate);
        getSettings().setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, retireJsAnalyzerEnabled);

        getSettings().setStringIfNotEmpty(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, hostedSuppressionsUrl);
        getSettings().setIntIfNotNull(Settings.KEYS.HOSTED_SUPPRESSIONS_VALID_FOR_HOURS, hostedSuppressionsValidForHours);
        getSettings().setStringIfNotNull(Settings.KEYS.HOSTED_SUPPRESSIONS_USER, hostedSuppressionsUser);
        getSettings().setStringIfNotNull(Settings.KEYS.HOSTED_SUPPRESSIONS_PASSWORD, hostedSuppressionsPassword);
        getSettings().setStringIfNotNull(Settings.KEYS.HOSTED_SUPPRESSIONS_BEARER_TOKEN, hostedSuppressionsBearerToken);
        getSettings().setBooleanIfNotNull(Settings.KEYS.HOSTED_SUPPRESSIONS_FORCEUPDATE, hostedSuppressionsForceUpdate);
        getSettings().setBooleanIfNotNull(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, hostedSuppressionsEnabled);

        getSettings().setStringIfNotEmpty(Settings.KEYS.NVD_API_KEY, nvdApiKey);
        getSettings().setStringIfNotEmpty(Settings.KEYS.NVD_API_ENDPOINT, nvdApiEndpoint);
        getSettings().setIntIfNotNull(Settings.KEYS.NVD_API_DELAY, nvdApiDelay);
        getSettings().setIntIfNotNull(Settings.KEYS.NVD_API_RESULTS_PER_PAGE, nvdApiResultsPerPage);
        getSettings().setStringIfNotEmpty(Settings.KEYS.NVD_API_DATAFEED_URL, nvdDatafeedUrl);
        getSettings().setStringIfNotEmpty(Settings.KEYS.NVD_API_DATAFEED_USER, nvdUser);
        getSettings().setStringIfNotEmpty(Settings.KEYS.NVD_API_DATAFEED_PASSWORD, nvdPassword);
        getSettings().setStringIfNotEmpty(Settings.KEYS.NVD_API_DATAFEED_BEARER_TOKEN, nvdBearerToken);
        getSettings().setIntIfNotNull(Settings.KEYS.NVD_API_MAX_RETRY_COUNT, nvdMaxRetryCount);
        getSettings().setIntIfNotNull(Settings.KEYS.NVD_API_VALID_FOR_HOURS, nvdValidForHours);
    }
}
