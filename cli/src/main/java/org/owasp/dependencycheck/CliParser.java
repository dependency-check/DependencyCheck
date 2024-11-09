/*
 * This file is part of dependency-check-cli.
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
package org.owasp.dependencycheck;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.File;
import java.io.FileNotFoundException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.owasp.dependencycheck.reporting.ReportGenerator.Format;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A utility to parse command line arguments for the DependencyCheck.
 *
 * @author Jeremy Long
 */
//suppress hard-coded password rule
@SuppressWarnings("squid:S2068")
public final class CliParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CliParser.class);
    /**
     * The command line.
     */
    private CommandLine line;
    /**
     * Indicates whether the arguments are valid.
     */
    private boolean isValid = true;
    /**
     * The configured settings.
     */
    private final Settings settings;
    /**
     * The supported reported formats.
     */
    private static final String SUPPORTED_FORMATS = "HTML, XML, CSV, JSON, JUNIT, SARIF, JENKINS, GITLAB or ALL";

    /**
     * Constructs a new CLI Parser object with the configured settings.
     *
     * @param settings the configured settings
     */
    public CliParser(Settings settings) {
        this.settings = settings;
    }

    /**
     * Parses the arguments passed in and captures the results for later use.
     *
     * @param args the command line arguments
     * @throws FileNotFoundException is thrown when a 'file' argument does not
     * point to a file that exists.
     * @throws ParseException is thrown when a Parse Exception occurs.
     */
    public void parse(String[] args) throws FileNotFoundException, ParseException {
        line = parseArgs(args);

        if (line != null) {
            validateArgs();
        }
    }

    /**
     * Parses the command line arguments.
     *
     * @param args the command line arguments
     * @return the results of parsing the command line arguments
     * @throws ParseException if the arguments are invalid
     */
    private CommandLine parseArgs(String[] args) throws ParseException {
        final CommandLineParser parser = new DefaultParser();
        final Options options = createCommandLineOptions();
        return parser.parse(options, args);
    }

    /**
     * Validates that the command line arguments are valid.
     *
     * @throws FileNotFoundException if there is a file specified by either the
     * SCAN or CPE command line arguments that does not exist.
     * @throws ParseException is thrown if there is an exception parsing the
     * command line.
     */
    private void validateArgs() throws FileNotFoundException, ParseException {
        if (isUpdateOnly() || isRunScan()) {

            String value = line.getOptionValue(ARGUMENT.NVD_API_VALID_FOR_HOURS);
            if (value != null) {
                try {
                    final int i = Integer.parseInt(value);
                    if (i < 0) {
                        throw new ParseException("Invalid Setting: nvdValidForHours must be a number greater than or equal to 0.");
                    }
                } catch (NumberFormatException ex) {
                    throw new ParseException("Invalid Setting: nvdValidForHours must be a number greater than or equal to 0.");
                }
            }
            value = line.getOptionValue(ARGUMENT.NVD_API_MAX_RETRY_COUNT);
            if (value != null) {
                try {
                    final int i = Integer.parseInt(value);
                    if (i <= 0) {
                        throw new ParseException("Invalid Setting: nvdMaxRetryCount must be a number greater than 0.");
                    }
                } catch (NumberFormatException ex) {
                    throw new ParseException("Invalid Setting: nvdMaxRetryCount must be a number greater than 0.");
                }
            }
            value = line.getOptionValue(ARGUMENT.NVD_API_DELAY);
            if (value != null) {
                try {
                    final int i = Integer.parseInt(value);
                    if (i < 0) {
                        throw new ParseException("Invalid Setting: nvdApiDelay must be a number greater than or equal to 0.");
                    }
                } catch (NumberFormatException ex) {
                    throw new ParseException("Invalid Setting: nvdApiDelay must be a number greater than or equal to 0.");
                }
            }
            value = line.getOptionValue(ARGUMENT.NVD_API_RESULTS_PER_PAGE);
            if (value != null) {
                try {
                    final int i = Integer.parseInt(value);
                    if (i <= 0 || i > 2000) {
                        throw new ParseException("Invalid Setting: nvdApiResultsPerPage must be a number in the range [1, 2000].");
                    }
                } catch (NumberFormatException ex) {
                    throw new ParseException("Invalid Setting: nvdApiResultsPerPage must be a number in the range [1, 2000].");
                }
            }
        }
        if (isRunScan()) {
            validatePathExists(getScanFiles(), ARGUMENT.SCAN);
            validatePathExists(getReportDirectory(), ARGUMENT.OUT);
            final String pathToCore = getStringArgument(ARGUMENT.PATH_TO_CORE);
            if (pathToCore != null) {
                validatePathExists(pathToCore, ARGUMENT.PATH_TO_CORE);
            }
            if (line.hasOption(ARGUMENT.OUTPUT_FORMAT)) {
                for (String validating : getReportFormat()) {
                    if (!isValidFormat(validating)
                            && !isValidFilePath(validating, "format")) {
                        final String msg = String.format("An invalid 'format' of '%s' was specified. "
                                + "Supported output formats are %s, and custom template files.",
                                validating, SUPPORTED_FORMATS);
                        throw new ParseException(msg);
                    }
                }
            }
            if (line.hasOption(ARGUMENT.SYM_LINK_DEPTH)) {
                try {
                    final int i = Integer.parseInt(line.getOptionValue(ARGUMENT.SYM_LINK_DEPTH));
                    if (i < 0) {
                        throw new ParseException("Symbolic Link Depth (symLink) must be greater than zero.");
                    }
                } catch (NumberFormatException ex) {
                    throw new ParseException("Symbolic Link Depth (symLink) is not a number.");
                }
            }
        }
    }

    /**
     * Validates the format to be one of the known Formats.
     *
     * @param format the format to validate
     * @return true, if format is known in Format; false otherwise
     * @see Format
     */
    private boolean isValidFormat(String format) {
        try {
            Format.valueOf(format);
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    /**
     * Validates the path to point at an existing file.
     *
     * @param path the path to validate if it exists
     * @param argumentName the argument being validated (e.g. scan, out, etc.)
     * @return true, if path exists; false otherwise
     */
    private boolean isValidFilePath(String path, String argumentName) {
        try {
            validatePathExists(path, argumentName);
            return true;
        } catch (FileNotFoundException ex) {
            return false;
        }
    }

    /**
     * Validates whether or not the path(s) points at a file that exists; if the
     * path(s) does not point to an existing file a FileNotFoundException is
     * thrown.
     *
     * @param paths the paths to validate if they exists
     * @param optType the option being validated (e.g. scan, out, etc.)
     * @throws FileNotFoundException is thrown if one of the paths being
     * validated does not exist.
     */
    private void validatePathExists(String[] paths, String optType) throws FileNotFoundException {
        for (String path : paths) {
            validatePathExists(path, optType);
        }
    }

    /**
     * Validates whether or not the path points at a file that exists; if the
     * path does not point to an existing file a FileNotFoundException is
     * thrown.
     *
     * @param path the paths to validate if they exists
     * @param argumentName the argument being validated (e.g. scan, out, etc.)
     * @throws FileNotFoundException is thrown if the path being validated does
     * not exist.
     */
    private void validatePathExists(String path, String argumentName) throws FileNotFoundException {
        if (path == null) {
            isValid = false;
            final String msg = String.format("Invalid '%s' argument: null", argumentName);
            throw new FileNotFoundException(msg);
        } else if (!path.contains("*") && !path.contains("?")) {
            File f = new File(path);
            final String[] formats = this.getReportFormat();
            if ("o".equalsIgnoreCase(argumentName.substring(0, 1)) && formats.length == 1 && !"ALL".equalsIgnoreCase(formats[0])) {
                final String checkPath = path.toLowerCase();
                if (checkPath.endsWith(".html") || checkPath.endsWith(".xml") || checkPath.endsWith(".htm")
                        || checkPath.endsWith(".csv") || checkPath.endsWith(".json")) {
                    if (f.getParentFile() == null) {
                        f = new File(".", path);
                    }
                    if (!f.getParentFile().isDirectory()) {
                        isValid = false;
                        final String msg = String.format("Invalid '%s' argument: '%s' - directory path does not exist", argumentName, path);
                        throw new FileNotFoundException(msg);
                    }
                }
            } else if ("o".equalsIgnoreCase(argumentName.substring(0, 1)) && !f.isDirectory()) {
                if (f.getParentFile() != null && f.getParentFile().isDirectory() && !f.mkdir()) {
                    isValid = false;
                    final String msg = String.format("Invalid '%s' argument: '%s' - unable to create the output directory", argumentName, path);
                    throw new FileNotFoundException(msg);
                }
                if (!f.isDirectory()) {
                    isValid = false;
                    final String msg = String.format("Invalid '%s' argument: '%s' - path does not exist", argumentName, path);
                    throw new FileNotFoundException(msg);
                }
            } else if (!f.exists()) {
                isValid = false;
                final String msg = String.format("Invalid '%s' argument: '%s' - path does not exist", argumentName, path);
                throw new FileNotFoundException(msg);
            }
//        } else if (path.startsWith("//") || path.startsWith("\\\\")) {
//            isValid = false;
//            final String msg = String.format("Invalid '%s' argument: '%s'%nUnable to scan paths that start with '//'.", argumentName, path);
//            throw new FileNotFoundException(msg);
        } else if ((path.endsWith("/*") && !path.endsWith("**/*")) || (path.endsWith("\\*") && path.endsWith("**\\*"))) {
            LOGGER.warn("Possibly incorrect path '{}' from argument '{}' because it ends with a slash star; "
                    + "dependency-check uses ant-style paths", path, argumentName);
        }
    }

    /**
     * Generates an Options collection that is used to parse the command line
     * and to display the help message.
     *
     * @return the command line options used for parsing the command line
     */
    @SuppressWarnings("static-access")
    private Options createCommandLineOptions() {
        final Options options = new Options();
        addStandardOptions(options);
        addAdvancedOptions(options);
        addDeprecatedOptions(options);
        return options;
    }

    /**
     * Adds the standard command line options to the given options collection.
     *
     * @param options a collection of command line arguments
     */
    @SuppressWarnings("static-access")
    private void addStandardOptions(final Options options) {
        //This is an option group because it can be specified more then once.

        options.addOptionGroup(newOptionGroup(newOptionWithArg(ARGUMENT.SCAN_SHORT, ARGUMENT.SCAN, "path",
                "The path to scan - this option can be specified multiple times. Ant style paths are supported (e.g. 'path/**/*.jar'); "
                + "if using Ant style paths it is highly recommended to quote the argument value.")))
                .addOptionGroup(newOptionGroup(newOptionWithArg(ARGUMENT.EXCLUDE, "pattern", "Specify an exclusion pattern. This option "
                        + "can be specified multiple times and it accepts Ant style exclusions.")))
                .addOption(newOptionWithArg(ARGUMENT.PROJECT, "name", "The name of the project being scanned."))
                .addOption(newOptionWithArg(ARGUMENT.OUT_SHORT, ARGUMENT.OUT, "path",
                        "The folder to write reports to. This defaults to the current directory. It is possible to set this to a specific "
                        + "file name if the format argument is not set to ALL."))
                .addOption(newOptionWithArg(ARGUMENT.OUTPUT_FORMAT_SHORT, ARGUMENT.OUTPUT_FORMAT, "format",
                        "The report format (" + SUPPORTED_FORMATS + "). The default is HTML. Multiple format parameters can be specified."))
                .addOption(newOption(ARGUMENT.PRETTY_PRINT, "When specified the JSON and XML report formats will be pretty printed."))
                .addOption(newOption(ARGUMENT.VERSION_SHORT, ARGUMENT.VERSION, "Print the version information."))
                .addOption(newOption(ARGUMENT.HELP_SHORT, ARGUMENT.HELP, "Print this message."))
                .addOption(newOption(ARGUMENT.ADVANCED_HELP, "Print the advanced help message."))
                .addOption(newOption(ARGUMENT.DISABLE_AUTO_UPDATE_SHORT, ARGUMENT.DISABLE_AUTO_UPDATE,
                        "Disables the automatic updating of the NVD-CVE, hosted-suppressions and RetireJS data."))
                .addOption(newOptionWithArg(ARGUMENT.VERBOSE_LOG_SHORT, ARGUMENT.VERBOSE_LOG, "file",
                        "The file path to write verbose logging information."))
                .addOptionGroup(newOptionGroup(newOptionWithArg(ARGUMENT.SUPPRESSION_FILES, "file",
                        "The file path to the suppression XML file. This can be specified more then once to utilize multiple suppression files")))
                .addOption(newOption(ARGUMENT.DISABLE_VERSION_CHECK, "Disables the dependency-check version check"))
                .addOption(newOption(ARGUMENT.EXPERIMENTAL, "Enables the experimental analyzers."))
                .addOption(newOptionWithArg(ARGUMENT.NVD_API_KEY, "apiKey", "The API Key to access the NVD API."))
                .addOption(newOptionWithArg(ARGUMENT.FAIL_ON_CVSS, "score",
                        "Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is 11; "
                        + "since the CVSS scores are 0-10, by default the build will never fail."))
                .addOption(newOptionWithArg(ARGUMENT.FAIL_JUNIT_ON_CVSS, "score",
                        "Specifies the CVSS score that is considered a failure when generating the junit report. The default is 0."));
    }

    /**
     * Adds the advanced command line options to the given options collection.
     * These are split out for purposes of being able to display two different
     * help messages.
     *
     * @param options a collection of command line arguments
     */
    @SuppressWarnings("static-access")
    private void addAdvancedOptions(final Options options) {
        options
                .addOption(newOption(ARGUMENT.UPDATE_ONLY,
                        "Only update the local NVD data cache; no scan will be executed."))
                .addOption(newOptionWithArg(ARGUMENT.NVD_API_DELAY, "milliseconds",
                        "Time in milliseconds to wait between downloading from the NVD."))
                .addOption(newOptionWithArg(ARGUMENT.NVD_API_RESULTS_PER_PAGE, "count",
                        "The number records for a single page from NVD API (must be <=2000)."))
                .addOption(newOptionWithArg(ARGUMENT.NVD_API_ENDPOINT, "endpoint",
                        "The NVD API Endpoint - setting this is rare."))
                .addOption(newOptionWithArg(ARGUMENT.NVD_API_DATAFEED_URL, "url",
                        "The URL to the NVD API Datafeed."))
                .addOption(newOptionWithArg(ARGUMENT.NVD_API_DATAFEED_USER, "user",
                        "Credentials for basic authentication to the NVD API Datafeed."))
                .addOption(newOptionWithArg(ARGUMENT.NVD_API_DATAFEED_PASSWORD, "password",
                        "Credentials for basic authentication to the NVD API Datafeed."))
                .addOption(newOptionWithArg(ARGUMENT.NVD_API_MAX_RETRY_COUNT, "count",
                        "The maximum number of retry requests for a single call to the NVD API."))
                .addOption(newOptionWithArg(ARGUMENT.NVD_API_VALID_FOR_HOURS, "hours",
                        "The number of hours to wait before checking for new updates from the NVD."))
                .addOption(newOptionWithArg(ARGUMENT.PROXY_PORT, "port",
                        "The proxy port to use when downloading resources."))
                .addOption(newOptionWithArg(ARGUMENT.PROXY_SERVER, "server",
                        "The proxy server to use when downloading resources."))
                .addOption(newOptionWithArg(ARGUMENT.PROXY_USERNAME, "user",
                        "The proxy username to use when downloading resources."))
                .addOption(newOptionWithArg(ARGUMENT.PROXY_PASSWORD, "pass",
                        "The proxy password to use when downloading resources."))
                .addOption(newOptionWithArg(ARGUMENT.NON_PROXY_HOSTS, "list",
                        "The proxy exclusion list: hostnames (or patterns) for which proxy should not be used. "
                        + "Use pipe, comma or colon as list separator."))
                .addOption(newOptionWithArg(ARGUMENT.CONNECTION_TIMEOUT_SHORT, ARGUMENT.CONNECTION_TIMEOUT, "timeout",
                        "The connection timeout (in milliseconds) to use when downloading resources."))
                .addOption(newOptionWithArg(ARGUMENT.CONNECTION_READ_TIMEOUT, "timeout",
                        "The read timeout (in milliseconds) to use when downloading resources."))
                .addOption(newOptionWithArg(ARGUMENT.CONNECTION_STRING, "connStr",
                        "The connection string to the database."))
                .addOption(newOptionWithArg(ARGUMENT.DB_NAME, "user",
                        "The username used to connect to the database."))
                .addOption(newOptionWithArg(ARGUMENT.DATA_DIRECTORY_SHORT, ARGUMENT.DATA_DIRECTORY, "path",
                        "The location of the H2 Database file. This option should generally not be set."))
                .addOption(newOptionWithArg(ARGUMENT.DB_PASSWORD, "password",
                        "The password for connecting to the database."))
                .addOption(newOptionWithArg(ARGUMENT.DB_DRIVER, "driver",
                        "The database driver name."))
                .addOption(newOptionWithArg(ARGUMENT.DB_DRIVER_PATH, "path",
                        "The path to the database driver; note, this does not need to be set unless the JAR is "
                        + "outside of the classpath."))
                .addOption(newOptionWithArg(ARGUMENT.SYM_LINK_DEPTH, "depth",
                        "Sets how deep nested symbolic links will be followed; 0 indicates symbolic links will not be followed."))
                .addOption(newOptionWithArg(ARGUMENT.PATH_TO_BUNDLE_AUDIT, "path",
                        "The path to bundle-audit for Gem bundle analysis."))
                .addOption(newOptionWithArg(ARGUMENT.PATH_TO_BUNDLE_AUDIT_WORKING_DIRECTORY, "path",
                        "The path to working directory that the bundle-audit command should be executed from when "
                        + "doing Gem bundle analysis."))
                .addOption(newOptionWithArg(ARGUMENT.CENTRAL_URL, "url",
                        "Alternative URL for Maven Central Search. If not set the public Sonatype Maven Central will be used."))
                .addOption(newOptionWithArg(ARGUMENT.OSSINDEX_URL, "url",
                        "Alternative URL for the OSS Index. If not set the public Sonatype OSS Index will be used."))
                .addOption(newOptionWithArg(ARGUMENT.OSSINDEX_USERNAME, "username",
                        "The username to authenticate to Sonatype's OSS Index. If not set the Sonatype OSS Index "
                        + "Analyzer will use an unauthenticated connection."))
                .addOption(newOptionWithArg(ARGUMENT.OSSINDEX_PASSWORD, "password", ""
                        + "The password to authenticate to Sonatype's OSS Index. If not set the Sonatype OSS "
                        + "Index Analyzer will use an unauthenticated connection."))
                .addOption(newOptionWithArg(ARGUMENT.OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, "true/false", ""
                        + "Whether a Sonatype OSS Index remote error should result in a warning only or a failure."))
                .addOption(newOption(ARGUMENT.RETIRE_JS_FORCEUPDATE, "Force the RetireJS Analyzer to update "
                        + "even if autoupdate is disabled"))
                .addOption(newOptionWithArg(ARGUMENT.RETIREJS_URL, "url",
                        "The Retire JS Repository URL"))
                .addOption(newOptionWithArg(ARGUMENT.RETIREJS_URL_USER, "username",
                        "The password to authenticate to Retire JS Repository URL"))
                .addOption(newOptionWithArg(ARGUMENT.RETIREJS_URL_PASSWORD, "password",
                        "The password to authenticate to Retire JS Repository URL"))
                .addOption(newOption(ARGUMENT.RETIREJS_FILTER_NON_VULNERABLE, "Specifies that the Retire JS "
                        + "Analyzer should filter out non-vulnerable JS files from the report."))
                .addOption(newOptionWithArg(ARGUMENT.ARTIFACTORY_PARALLEL_ANALYSIS, "true/false",
                        "Whether the Artifactory Analyzer should use parallel analysis."))
                .addOption(newOptionWithArg(ARGUMENT.ARTIFACTORY_USES_PROXY, "true/false",
                        "Whether the Artifactory Analyzer should use the proxy."))
                .addOption(newOptionWithArg(ARGUMENT.ARTIFACTORY_USERNAME, "username",
                        "The Artifactory username for authentication."))
                .addOption(newOptionWithArg(ARGUMENT.ARTIFACTORY_API_TOKEN, "token",
                        "The Artifactory API token."))
                .addOption(newOptionWithArg(ARGUMENT.ARTIFACTORY_BEARER_TOKEN, "token",
                        "The Artifactory bearer token."))
                .addOption(newOptionWithArg(ARGUMENT.ARTIFACTORY_URL, "url",
                        "The Artifactory URL."))
                .addOption(newOptionWithArg(ARGUMENT.PATH_TO_GO, "path",
                        "The path to the `go` executable."))
                .addOption(newOptionWithArg(ARGUMENT.PATH_TO_YARN, "path",
                        "The path to the `yarn` executable."))
                .addOption(newOptionWithArg(ARGUMENT.PATH_TO_PNPM, "path",
                        "The path to the `pnpm` executable."))
                .addOption(newOptionWithArg(ARGUMENT.RETIREJS_FILTERS, "pattern",
                        "Specify Retire JS content filter used to exclude files from analysis based on their content; "
                        + "most commonly used to exclude based on your applications own copyright line. This "
                        + "option can be specified multiple times."))
                .addOption(newOptionWithArg(ARGUMENT.NEXUS_URL, "url",
                        "The url to the Nexus Server's REST API Endpoint (http://domain/nexus/service/local). If not "
                        + "set the Nexus Analyzer will be disabled."))
                .addOption(newOptionWithArg(ARGUMENT.NEXUS_USERNAME, "username",
                        "The username to authenticate to the Nexus Server's REST API Endpoint. If not set the Nexus "
                        + "Analyzer will use an unauthenticated connection."))
                .addOption(newOptionWithArg(ARGUMENT.NEXUS_PASSWORD, "password",
                        "The password to authenticate to the Nexus Server's REST API Endpoint. If not set the Nexus "
                        + "Analyzer will use an unauthenticated connection."))
                //TODO remove as this should be covered by non-proxy hosts
                .addOption(newOptionWithArg(ARGUMENT.NEXUS_USES_PROXY, "true/false",
                        "Whether or not the configured proxy should be used when connecting to Nexus."))
                .addOption(newOptionWithArg(ARGUMENT.ADDITIONAL_ZIP_EXTENSIONS, "extensions",
                        "A comma separated list of additional extensions to be scanned as ZIP files (ZIP, EAR, WAR "
                        + "are already treated as zip files)"))
                .addOption(newOptionWithArg(ARGUMENT.PROP_SHORT, ARGUMENT.PROP, "file", "A property file to load."))
                .addOption(newOptionWithArg(ARGUMENT.PATH_TO_CORE, "path", "The path to dotnet core."))
                .addOption(newOptionWithArg(ARGUMENT.HINTS_FILE, "file", "The file path to the hints XML file."))
                .addOption(newOption(ARGUMENT.RETIRED, "Enables the retired analyzers."))
                .addOption(newOption(ARGUMENT.DISABLE_MSBUILD, "Disable the MS Build Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_JAR, "Disable the Jar Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_ARCHIVE, "Disable the Archive Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_KEV, "Disable the Known Exploited Vulnerability Analyzer."))
                .addOption(newOptionWithArg(ARGUMENT.KEV_URL, "url", "The url to the CISA Known Exploited Vulnerabilities JSON data feed"))
                .addOption(newOption(ARGUMENT.DISABLE_ASSEMBLY, "Disable the .NET Assembly Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_PY_DIST, "Disable the Python Distribution Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_CMAKE, "Disable the Cmake Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_PY_PKG, "Disable the Python Package Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_MIX_AUDIT, "Disable the Elixir mix_audit Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_RUBYGEMS, "Disable the Ruby Gemspec Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_BUNDLE_AUDIT, "Disable the Ruby Bundler-Audit Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_FILENAME, "Disable the File Name Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_AUTOCONF, "Disable the Autoconf Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_MAVEN_INSTALL, "Disable the Maven install Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_PIP, "Disable the pip Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_PIPFILE, "Disable the Pipfile Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_COMPOSER, "Disable the PHP Composer Analyzer."))
                .addOption(newOption(ARGUMENT.COMPOSER_LOCK_SKIP_DEV, "Configures the PHP Composer Analyzer to skip packages-dev"))
                .addOption(newOption(ARGUMENT.DISABLE_CPAN, "Disable the Perl CPAN file Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_POETRY, "Disable the Poetry Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_GOLANG_MOD, "Disable the Golang Mod Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_DART, "Disable the Dart Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_OPENSSL, "Disable the OpenSSL Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_NUSPEC, "Disable the Nuspec Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_NUGETCONF, "Disable the Nuget packages.config Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_CENTRAL, "Disable the Central Analyzer. If this analyzer "
                        + "is disabled it is likely you also want to disable the Nexus Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_CENTRAL_CACHE, "Disallow the Central Analyzer from caching results"))
                .addOption(newOption(ARGUMENT.DISABLE_OSSINDEX, "Disable the Sonatype OSS Index Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_OSSINDEX_CACHE, "Disallow the OSS Index Analyzer from caching results"))
                .addOption(newOption(ARGUMENT.DISABLE_COCOAPODS, "Disable the CocoaPods Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_CARTHAGE, "Disable the Carthage Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_SWIFT, "Disable the swift package Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_SWIFT_RESOLVED, "Disable the swift package resolved Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_GO_DEP, "Disable the Golang Package Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_NODE_JS, "Disable the Node.js Package Analyzer."))
                .addOption(newOption(ARGUMENT.NODE_PACKAGE_SKIP_DEV_DEPENDENCIES, "Configures the Node Package Analyzer to skip devDependencies"))
                .addOption(newOption(ARGUMENT.DISABLE_NODE_AUDIT, "Disable the Node Audit Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_PNPM_AUDIT, "Disable the Pnpm Audit Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_YARN_AUDIT, "Disable the Yarn Audit Analyzer."))
                .addOption(newOption(ARGUMENT.DISABLE_NODE_AUDIT_CACHE, "Disallow the Node Audit Analyzer from caching results"))
                .addOption(newOption(ARGUMENT.DISABLE_NODE_AUDIT_SKIPDEV, "Configures the Node Audit Analyzer to skip devDependencies"))
                .addOption(newOption(ARGUMENT.DISABLE_RETIRE_JS, "Disable the RetireJS Analyzer."))
                .addOption(newOption(ARGUMENT.ENABLE_NEXUS, "Enable the Nexus Analyzer."))
                .addOption(newOption(ARGUMENT.ARTIFACTORY_ENABLED, "Whether the Artifactory Analyzer should be enabled."))
                .addOption(newOption(ARGUMENT.PURGE_NVD, "Purges the local NVD data cache"))
                .addOption(newOption(ARGUMENT.DISABLE_HOSTED_SUPPRESSIONS, "Disable the usage of the hosted suppressions file"))
                .addOption(newOption(ARGUMENT.HOSTED_SUPPRESSIONS_FORCEUPDATE, "Force the hosted suppressions file to update even"
                        + " if autoupdate is disabled"))
                .addOption(newOptionWithArg(ARGUMENT.HOSTED_SUPPRESSIONS_VALID_FOR_HOURS, "hours",
                        "The number of hours to wait before checking for new updates of the the hosted suppressions file."))
                .addOption(newOptionWithArg(ARGUMENT.HOSTED_SUPPRESSIONS_URL, "url",
                        "The URL for a mirrored hosted suppressions file"));

    }

    /**
     * Adds the deprecated command line options to the given options collection.
     * These are split out for purposes of not including them in the help
     * message. We need to add the deprecated options so as not to break
     * existing scripts.
     *
     * @param options a collection of command line arguments
     */
    @SuppressWarnings({"static-access", "deprecation"})
    private void addDeprecatedOptions(final Options options) {
        //not a real option - but enables java debugging via the shell script
        options.addOption(newOption("debug",
                "Used to enable java debugging of the cli via dependency-check.sh."));
    }

    /**
     * Determines if the 'version' command line argument was passed in.
     *
     * @return whether or not the 'version' command line argument was passed in
     */
    public boolean isGetVersion() {
        return (line != null) && line.hasOption(ARGUMENT.VERSION);
    }

    /**
     * Determines if the 'help' command line argument was passed in.
     *
     * @return whether or not the 'help' command line argument was passed in
     */
    public boolean isGetHelp() {
        return (line != null) && line.hasOption(ARGUMENT.HELP);
    }

    /**
     * Determines if the 'scan' command line argument was passed in.
     *
     * @return whether or not the 'scan' command line argument was passed in
     */
    public boolean isRunScan() {
        return (line != null) && isValid && line.hasOption(ARGUMENT.SCAN);
    }

    /**
     * Returns the symbolic link depth (how deeply symbolic links will be
     * followed).
     *
     * @return the symbolic link depth
     */
    public int getSymLinkDepth() {
        int value = 0;
        try {
            value = Integer.parseInt(line.getOptionValue(ARGUMENT.SYM_LINK_DEPTH, "0"));
            if (value < 0) {
                value = 0;
            }
        } catch (NumberFormatException ex) {
            LOGGER.debug("Symbolic link was not a number");
        }
        return value;
    }

    /**
     * Utility method to determine if one of the disable options has been set.
     * If not set, this method will check the currently configured settings for
     * the current value to return.
     * <p>
     * Example given `--disableArchive` on the command line would cause this
     * method to return true for the disable archive setting.
     *
     * @param disableFlag the command line disable option
     * @param setting the corresponding settings key
     * @return true if the disable option was set, if not set the currently
     * configured value will be returned
     */
    public boolean isDisabled(String disableFlag, String setting) {
        if (line == null || !line.hasOption(disableFlag)) {
            try {
                return !settings.getBoolean(setting);
            } catch (InvalidSettingException ise) {
                LOGGER.warn("Invalid property setting '{}' defaulting to false", setting);
                return false;
            }
        } else {
            return true;
        }
    }

    /**
     * Returns true if the disableNodeAudit command line argument was specified.
     *
     * @return true if the disableNodeAudit command line argument was specified;
     * otherwise false
     */
    public boolean isNodeAuditDisabled() {
        return isDisabled(ARGUMENT.DISABLE_NODE_AUDIT, Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED);
    }

    /**
     * Returns true if the disableYarnAudit command line argument was specified.
     *
     * @return true if the disableYarnAudit command line argument was specified;
     * otherwise false
     */
    public boolean isYarnAuditDisabled() {
        return isDisabled(ARGUMENT.DISABLE_YARN_AUDIT, Settings.KEYS.ANALYZER_YARN_AUDIT_ENABLED);
    }

    /**
     * Returns true if the disablePnpmAudit command line argument was specified.
     *
     * @return true if the disablePnpmAudit command line argument was specified;
     * otherwise false
     */
    public boolean isPnpmAuditDisabled() {
        return isDisabled(ARGUMENT.DISABLE_PNPM_AUDIT, Settings.KEYS.ANALYZER_PNPM_AUDIT_ENABLED);
    }

    /**
     * Returns true if the Nexus Analyzer should use the configured proxy to
     * connect to Nexus; otherwise false is returned.
     *
     * @return true if the Nexus Analyzer should use the configured proxy to
     * connect to Nexus; otherwise false
     */
    public boolean isNexusUsesProxy() {
        // If they didn't specify whether Nexus needs to use the proxy, we should
        // still honor the property if it's set.
        if (line == null || !line.hasOption(ARGUMENT.NEXUS_USES_PROXY)) {
            try {
                return settings.getBoolean(Settings.KEYS.ANALYZER_NEXUS_USES_PROXY);
            } catch (InvalidSettingException ise) {
                return true;
            }
        } else {
            return Boolean.parseBoolean(line.getOptionValue(ARGUMENT.NEXUS_USES_PROXY));
        }
    }

    /**
     * Returns the argument boolean value.
     *
     * @param argument the argument
     * @return the argument boolean value
     */
    @SuppressFBWarnings(justification = "Accepting that this is a bad practice - used a Boolean as we needed three states",
            value = {"NP_BOOLEAN_RETURN_NULL"})
    public Boolean getBooleanArgument(String argument) {
        if (line != null && line.hasOption(argument)) {
            final String value = line.getOptionValue(argument);
            if (value != null) {
                return Boolean.parseBoolean(value);
            }
        }
        return null;
    }

    /**
     * Returns the argument value for the given option.
     *
     * @param option the option
     * @return the value of the argument
     */
    public String getStringArgument(String option) {
        return getStringArgument(option, null);
    }

    /**
     * Returns the argument value for the given option.
     *
     * @param option the option
     * @param key the dependency-check settings key for the option.
     * @return the value of the argument
     */
    public String getStringArgument(String option, String key) {
        if (line != null && line.hasOption(option)) {
            if (key != null && (option.toLowerCase().endsWith("password")
                    || option.toLowerCase().endsWith("pass"))) {
                LOGGER.warn("{} used on the command line, consider moving the password "
                        + "to a properties file using the key `{}` and using the "
                        + "--propertyfile argument instead", option, key);
            }
            return line.getOptionValue(option);
        }
        return null;
    }

    /**
     * Returns the argument value for the given option.
     *
     * @param option the option
     * @return the value of the argument
     */
    public String[] getStringArguments(String option) {
        if (line != null && line.hasOption(option)) {
            return line.getOptionValues(option);
        }
        return null;
    }

    /**
     * Returns the argument value for the given option.
     *
     * @param option the option
     * @return the value of the argument
     */
    public File getFileArgument(String option) {
        final String path = line.getOptionValue(option);
        if (path != null) {
            return new File(path);
        }
        return null;
    }

    /**
     * Displays the command line help message to the standard output.
     */
    public void printHelp() {
        final HelpFormatter formatter = new HelpFormatter();
        final Options options = new Options();
        addStandardOptions(options);
        if (line != null && line.hasOption(ARGUMENT.ADVANCED_HELP)) {
            addAdvancedOptions(options);
        }
        final String helpMsg = String.format("%n%s"
                + " can be used to identify if there are any known CVE vulnerabilities in libraries utilized by an application. "
                + "%s will automatically update required data from the Internet, such as the CVE and CPE data files from nvd.nist.gov.%n%n",
                settings.getString(Settings.KEYS.APPLICATION_NAME, "DependencyCheck"),
                settings.getString(Settings.KEYS.APPLICATION_NAME, "DependencyCheck"));

        formatter.printHelp(settings.getString(Settings.KEYS.APPLICATION_NAME, "DependencyCheck"),
                helpMsg,
                options,
                "",
                true);
    }

    /**
     * Retrieves the file command line parameter(s) specified for the 'scan'
     * argument.
     *
     * @return the file paths specified on the command line for scan
     */
    public String[] getScanFiles() {
        return line.getOptionValues(ARGUMENT.SCAN);
    }

    /**
     * Retrieves the list of excluded file patterns specified by the 'exclude'
     * argument.
     *
     * @return the excluded file patterns
     */
    public String[] getExcludeList() {
        return line.getOptionValues(ARGUMENT.EXCLUDE);
    }

    /**
     * Retrieves the list of retire JS content filters used to exclude JS files
     * by content.
     *
     * @return the retireJS filters
     */
    public String[] getRetireJsFilters() {
        return line.getOptionValues(ARGUMENT.RETIREJS_FILTERS);
    }

    /**
     * Returns whether or not the retireJS analyzer should exclude
     * non-vulnerable JS from the report.
     *
     * @return <code>true</code> if non-vulnerable JS should be filtered in the
     * RetireJS Analyzer; otherwise <code>null</code>
     */
    @SuppressFBWarnings(justification = "Accepting that this is a bad practice - but made more sense in this use case",
            value = {"NP_BOOLEAN_RETURN_NULL"})
    public Boolean isRetireJsFilterNonVulnerable() {
        return (line != null && line.hasOption(ARGUMENT.RETIREJS_FILTER_NON_VULNERABLE)) ? true : null;
    }

    /**
     * Returns the directory to write the reports to specified on the command
     * line.
     *
     * @return the path to the reports directory.
     */
    public String getReportDirectory() {
        return line.getOptionValue(ARGUMENT.OUT, ".");
    }

    /**
     * Returns the output format specified on the command line. Defaults to HTML
     * if no format was specified.
     *
     * @return the output format name.
     */
    public String[] getReportFormat() {
        if (line.hasOption(ARGUMENT.OUTPUT_FORMAT)) {
            return line.getOptionValues(ARGUMENT.OUTPUT_FORMAT);
        }
        return new String[]{"HTML"};
    }

    /**
     * Returns the application name specified on the command line.
     *
     * @return the application name.
     */
    public String getProjectName() {
        String name = line.getOptionValue(ARGUMENT.PROJECT);
        if (name == null) {
            name = "";
        }
        return name;
    }

    /**
     * <p>
     * Prints the manifest information to standard output.</p>
     * <ul><li>Implementation-Title: ${pom.name}</li>
     * <li>Implementation-Version: ${pom.version}</li></ul>
     */
    public void printVersionInfo() {
        final String version = String.format("%s version %s",
                settings.getString(Settings.KEYS.APPLICATION_NAME, "dependency-check"),
                settings.getString(Settings.KEYS.APPLICATION_VERSION, "Unknown"));
        System.out.println(version);
    }

    /**
     * Checks if the update only flag has been set.
     *
     * @return <code>true</code> if the update only flag has been set; otherwise
     * <code>false</code>.
     */
    public boolean isUpdateOnly() {
        return line != null && line.hasOption(ARGUMENT.UPDATE_ONLY);
    }

    /**
     * Checks if the purge NVD flag has been set.
     *
     * @return <code>true</code> if the purge nvd flag has been set; otherwise
     * <code>false</code>.
     */
    public boolean isPurge() {
        return line != null && line.hasOption(ARGUMENT.PURGE_NVD);
    }

    /**
     * Returns the database driver name if specified; otherwise null is
     * returned.
     *
     * @return the database driver name if specified; otherwise null is returned
     */
    public String getDatabaseDriverName() {
        return line.getOptionValue(ARGUMENT.DB_DRIVER);
    }

    /**
     * Returns the argument value.
     *
     * @param argument the argument
     * @return the value of the argument
     */
    public Integer getIntegerValue(String argument) {
        final String v = line.getOptionValue(argument);
        if (v != null) {
            return Integer.parseInt(v);
        }
        return null;
    }

    /**
     * Checks if the option is present. If present it will return
     * <code>true</code>; otherwise <code>false</code>.
     *
     * @param option the option to check
     * @return <code>true</code> if auto-update is allowed; otherwise
     * <code>null</code>
     */
    @SuppressFBWarnings(justification = "Accepting that this is a bad practice - but made more sense in this use case",
            value = {"NP_BOOLEAN_RETURN_NULL"})
    public Boolean hasOption(String option) {
        return (line != null && line.hasOption(option)) ? true : null;
    }

    /**
     * Returns the CVSS value to fail on.
     *
     * @return 11 if nothing is set. Otherwise it returns the int passed from
     * the command line arg
     */
    public float getFailOnCVSS() {
        if (line.hasOption(ARGUMENT.FAIL_ON_CVSS)) {
            final String value = line.getOptionValue(ARGUMENT.FAIL_ON_CVSS);
            try {
                return Float.parseFloat(value);
            } catch (NumberFormatException nfe) {
                return 11;
            }
        } else {
            return 11;
        }
    }

    /**
     * Returns the float argument for the given option.
     *
     * @param option the option
     * @param defaultValue the value if the option is not present
     * @return the value of the argument if present; otherwise the defaultValue
     */
    public float getFloatArgument(String option, float defaultValue) {
        if (line.hasOption(option)) {
            final String value = line.getOptionValue(option);
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException nfe) {
                return defaultValue;
            }
        } else {
            return defaultValue;
        }
    }

    /**
     * Builds a new option.
     *
     * @param name the long name
     * @param description the description
     * @return a new option
     */
    private Option newOption(String name, String description) {
        return Option.builder().longOpt(name).desc(description).build();
    }

    /**
     * Builds a new option.
     *
     * @param shortName the short name
     * @param name the long name
     * @param description the description
     * @return a new option
     */
    private Option newOption(String shortName, String name, String description) {
        return Option.builder(shortName).longOpt(name).desc(description).build();
    }

    /**
     * Builds a new option.
     *
     * @param name the long name
     * @param arg the argument name
     * @param description the description
     * @return a new option
     */
    private Option newOptionWithArg(String name, String arg, String description) {
        return Option.builder().longOpt(name).argName(arg).hasArg().desc(description).build();
    }

    /**
     * Builds a new option.
     *
     * @param shortName the short name
     * @param name the long name
     * @param arg the argument name
     * @param description the description
     * @return a new option
     */
    private Option newOptionWithArg(String shortName, String name, String arg, String description) {
        return Option.builder(shortName).longOpt(name).argName(arg).hasArg().desc(description).build();
    }

    /**
     * Builds a new option group so that an option can be specified multiple
     * times on the command line.
     *
     * @param option the option to add to the group
     * @return a new option group
     */
    private OptionGroup newOptionGroup(Option option) {
        final OptionGroup group = new OptionGroup();
        group.addOption(option);
        return group;
    }

    /**
     * A collection of static final strings that represent the possible command
     * line arguments.
     */
    public static class ARGUMENT {

        /**
         * The long CLI argument name specifying the directory/file to scan.
         */
        public static final String SCAN = "scan";
        /**
         * The short CLI argument name specifying the directory/file to scan.
         */
        public static final String SCAN_SHORT = "s";
        /**
         * The long CLI argument name specifying that the CPE/CVE/etc. data
         * should not be automatically updated.
         */
        public static final String DISABLE_AUTO_UPDATE = "noupdate";
        /**
         * The long CLI argument name specifying that the version check should
         * not be performed.
         */
        public static final String DISABLE_VERSION_CHECK = "disableVersionCheck";
        /**
         * The short CLI argument name specifying that the CPE/CVE/etc. data
         * should not be automatically updated.
         */
        public static final String DISABLE_AUTO_UPDATE_SHORT = "n";
        /**
         * The long CLI argument name specifying that only the update phase
         * should be executed; no scan should be run.
         */
        public static final String UPDATE_ONLY = "updateonly";
        /**
         * The long CLI argument name specifying that only the update phase
         * should be executed; no scan should be run.
         */
        public static final String PURGE_NVD = "purge";
        /**
         * The long CLI argument name specifying the directory to write the
         * reports to.
         */
        public static final String OUT = "out";
        /**
         * The short CLI argument name specifying the directory to write the
         * reports to.
         */
        public static final String OUT_SHORT = "o";
        /**
         * The long CLI argument name specifying the output format to write the
         * reports to.
         */
        public static final String OUTPUT_FORMAT = "format";
        /**
         * The short CLI argument name specifying the output format to write the
         * reports to.
         */
        public static final String OUTPUT_FORMAT_SHORT = "f";
        /**
         * The long CLI argument name specifying the name of the project to be
         * scanned.
         */
        public static final String PROJECT = "project";
        /**
         * The long CLI argument name asking for help.
         */
        public static final String HELP = "help";
        /**
         * The long CLI argument name asking for advanced help.
         */
        public static final String ADVANCED_HELP = "advancedHelp";
        /**
         * The short CLI argument name asking for help.
         */
        public static final String HELP_SHORT = "h";
        /**
         * The long CLI argument name asking for the version.
         */
        public static final String VERSION_SHORT = "v";
        /**
         * The short CLI argument name asking for the version.
         */
        public static final String VERSION = "version";
        /**
         * The CLI argument name indicating the proxy port.
         */
        public static final String PROXY_PORT = "proxyport";
        /**
         * The CLI argument name indicating the proxy server.
         */
        public static final String PROXY_SERVER = "proxyserver";
        /**
         * The CLI argument name indicating the proxy username.
         */
        public static final String PROXY_USERNAME = "proxyuser";
        /**
         * The CLI argument name indicating the proxy password.
         */
        public static final String PROXY_PASSWORD = "proxypass";
        /**
         * The CLI argument name indicating the proxy proxy exclusion list.
         */
        public static final String NON_PROXY_HOSTS = "nonProxyHosts";
        /**
         * The short CLI argument name indicating the connection timeout.
         */
        public static final String CONNECTION_TIMEOUT_SHORT = "c";
        /**
         * The CLI argument name indicating the connection timeout.
         */
        public static final String CONNECTION_TIMEOUT = "connectiontimeout";
        /**
         * The CLI argument name indicating the connection read timeout.
         */
        public static final String CONNECTION_READ_TIMEOUT = "readtimeout";
        /**
         * The short CLI argument name for setting the location of an additional
         * properties file.
         */
        public static final String PROP_SHORT = "P";
        /**
         * The CLI argument name for setting the location of an additional
         * properties file.
         */
        public static final String PROP = "propertyfile";
        /**
         * The CLI argument name for setting the location of the data directory.
         */
        public static final String DATA_DIRECTORY = "data";
        /**
         * The CLI argument name for setting the URL for the NVD API Endpoint.
         */
        public static final String NVD_API_ENDPOINT = "nvdApiEndpoint";
        /**
         * The CLI argument name for setting the URL for the NVD API Key.
         */
        public static final String NVD_API_KEY = "nvdApiKey";
        /**
         * The CLI argument name for setting the maximum number of retry
         * requests for a single call to the NVD API.
         */
        public static final String NVD_API_MAX_RETRY_COUNT = "nvdMaxRetryCount";
        /**
         * The CLI argument name for setting the number of hours to wait before
         * checking for new updates from the NVD.
         */
        public static final String NVD_API_VALID_FOR_HOURS = "nvdValidForHours";
        /**
         * The CLI argument name for the NVD API Data Feed URL.
         */
        public static final String NVD_API_DATAFEED_URL = "nvdDatafeed";
        /**
         * The username for basic auth to the CVE data.
         */
        public static final String NVD_API_DATAFEED_USER = "nvdUser";
        /**
         * The password for basic auth to the CVE data.
         */
        public static final String NVD_API_DATAFEED_PASSWORD = "nvdPassword";
        /**
         * The time in milliseconds to wait between downloading NVD API data.
         */
        public static final String NVD_API_DELAY = "nvdApiDelay";
        /**
         * The number records for a single page from NVD API.
         */
        public static final String NVD_API_RESULTS_PER_PAGE = "nvdApiResultsPerPage";
        /**
         * The short CLI argument name for setting the location of the data
         * directory.
         */
        public static final String DATA_DIRECTORY_SHORT = "d";
        /**
         * The CLI argument name for setting the location of the data directory.
         */
        public static final String VERBOSE_LOG = "log";
        /**
         * The short CLI argument name for setting the location of the data
         * directory.
         */
        public static final String VERBOSE_LOG_SHORT = "l";
        /**
         * The CLI argument name for setting the depth of symbolic links that
         * will be followed.
         */
        public static final String SYM_LINK_DEPTH = "symLink";
        /**
         * The CLI argument name for setting the location of the suppression
         * file(s).
         */
        public static final String SUPPRESSION_FILES = "suppression";
        /**
         * The CLI argument name for setting the location of the hint file.
         */
        public static final String HINTS_FILE = "hints";
        /**
         * Disables the Jar Analyzer.
         */
        public static final String DISABLE_JAR = "disableJar";
        /**
         * Disable the MS Build Analyzer.
         */
        public static final String DISABLE_MSBUILD = "disableMSBuild";
        /**
         * Disables the Archive Analyzer.
         */
        public static final String DISABLE_ARCHIVE = "disableArchive";
        /**
         * Disables the Known Exploited Analyzer.
         */
        public static final String DISABLE_KEV = "disableKnownExploited";
        /**
         * The URL to the CISA Known Exploited Vulnerability JSON datafeed.
         */
        public static final String KEV_URL = "kevURL";
        /**
         * Disables the Python Distribution Analyzer.
         */
        public static final String DISABLE_PY_DIST = "disablePyDist";
        /**
         * Disables the Python Package Analyzer.
         */
        public static final String DISABLE_PY_PKG = "disablePyPkg";
        /**
         * Disables the Elixir mix audit Analyzer.
         */
        public static final String DISABLE_MIX_AUDIT = "disableMixAudit";
        /**
         * Disables the Golang Dependency Analyzer.
         */
        public static final String DISABLE_GO_DEP = "disableGolangDep";
        /**
         * Disables the PHP Composer Analyzer.
         */
        public static final String DISABLE_COMPOSER = "disableComposer";
        /**
         * Whether the PHP Composer Analyzer skips dev packages.
         */
        public static final String COMPOSER_LOCK_SKIP_DEV = "composerSkipDev";
        /**
         * Disables the Perl CPAN File Analyzer.
         */
        public static final String DISABLE_CPAN = "disableCpan";
        /**
         * Disables the Golang Mod Analyzer.
         */
        public static final String DISABLE_GOLANG_MOD = "disableGolangMod";
        /**
         * Disables the Dart Analyzer.
         */
        public static final String DISABLE_DART = "disableDart";
        /**
         * The CLI argument name for setting the path to `go`.
         */
        public static final String PATH_TO_GO = "go";
        /**
         * The CLI argument name for setting the path to `yarn`.
         */
        public static final String PATH_TO_YARN = "yarn";
        /**
         * The CLI argument name for setting the path to `pnpm`.
         */
        public static final String PATH_TO_PNPM = "pnpm";
        /**
         * Disables the Ruby Gemspec Analyzer.
         */
        public static final String DISABLE_RUBYGEMS = "disableRubygems";
        /**
         * Disables the Autoconf Analyzer.
         */
        public static final String DISABLE_AUTOCONF = "disableAutoconf";
        /**
         * Disables the Maven install Analyzer.
         */
        public static final String DISABLE_MAVEN_INSTALL = "disableMavenInstall";
        /**
         * Disables the pip Analyzer.
         */
        public static final String DISABLE_PIP = "disablePip";
        /**
         * Disables the Pipfile Analyzer.
         */
        public static final String DISABLE_PIPFILE = "disablePipfile";
        /**
         * Disables the Poetry Analyzer.
         */
        public static final String DISABLE_POETRY = "disablePoetry";
        /**
         * Disables the Cmake Analyzer.
         */
        public static final String DISABLE_CMAKE = "disableCmake";
        /**
         * Disables the cocoapods analyzer.
         */
        public static final String DISABLE_COCOAPODS = "disableCocoapodsAnalyzer";
        /**
         * Disables the Carthage analyzer.
         */
        public static final String DISABLE_CARTHAGE = "disableCarthageAnalyzer";
        /**
         * Disables the swift package manager analyzer.
         */
        public static final String DISABLE_SWIFT = "disableSwiftPackageManagerAnalyzer";
        /**
         * Disables the swift package resolved analyzer.
         */
        public static final String DISABLE_SWIFT_RESOLVED = "disableSwiftPackageResolvedAnalyzer";
        /**
         * Disables the Assembly Analyzer.
         */
        public static final String DISABLE_ASSEMBLY = "disableAssembly";
        /**
         * Disables the Ruby Bundler Audit Analyzer.
         */
        public static final String DISABLE_BUNDLE_AUDIT = "disableBundleAudit";
        /**
         * Disables the File Name Analyzer.
         */
        public static final String DISABLE_FILENAME = "disableFileName";
        /**
         * Disables the Nuspec Analyzer.
         */
        public static final String DISABLE_NUSPEC = "disableNuspec";
        /**
         * Disables the Nuget packages.config Analyzer.
         */
        public static final String DISABLE_NUGETCONF = "disableNugetconf";
        /**
         * Disables the Central Analyzer.
         */
        public static final String DISABLE_CENTRAL = "disableCentral";
        /**
         * Disables the Central Analyzer's ability to cache results locally.
         */
        public static final String DISABLE_CENTRAL_CACHE = "disableCentralCache";
        /**
         * The alternative URL for Maven Central Search.
         */
        public static final String CENTRAL_URL = "centralUrl";
        /**
         * Disables the Nexus Analyzer.
         */
        public static final String ENABLE_NEXUS = "enableNexus";
        /**
         * Disables the Sonatype OSS Index Analyzer.
         */
        public static final String DISABLE_OSSINDEX = "disableOssIndex";
        /**
         * Disables the Sonatype OSS Index Analyzer's ability to cache results
         * locally.
         */
        public static final String DISABLE_OSSINDEX_CACHE = "disableOssIndexCache";
        /**
         * The alternative URL for the Sonatype OSS Index.
         */
        public static final String OSSINDEX_URL = "ossIndexUrl";
        /**
         * The username for the Sonatype OSS Index.
         */
        public static final String OSSINDEX_USERNAME = "ossIndexUsername";
        /**
         * The password for the Sonatype OSS Index.
         */
        public static final String OSSINDEX_PASSWORD = "ossIndexPassword";
        /**
         * The password for the Sonatype OSS Index.
         */
        public static final String OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS = "ossIndexRemoteErrorWarnOnly";
        /**
         * Disables the OpenSSL Analyzer.
         */
        public static final String DISABLE_OPENSSL = "disableOpenSSL";
        /**
         * Disables the Node.js Package Analyzer.
         */
        public static final String DISABLE_NODE_JS = "disableNodeJS";
        /**
         * Skips dev dependencies in Node Package Analyzer.
         */
        public static final String NODE_PACKAGE_SKIP_DEV_DEPENDENCIES = "nodePackageSkipDevDependencies";
        /**
         * Disables the Node Audit Analyzer.
         */
        public static final String DISABLE_NODE_AUDIT = "disableNodeAudit";
        /**
         * Disables the Yarn Audit Analyzer.
         */
        public static final String DISABLE_YARN_AUDIT = "disableYarnAudit";
        /**
         * Disables the Pnpm Audit Analyzer.
         */
        public static final String DISABLE_PNPM_AUDIT = "disablePnpmAudit";
        /**
         * Disables the Node Audit Analyzer's ability to cache results locally.
         */
        public static final String DISABLE_NODE_AUDIT_CACHE = "disableNodeAuditCache";
        /**
         * Configures the Node Audit Analyzer to skip the dev dependencies.
         */
        public static final String DISABLE_NODE_AUDIT_SKIPDEV = "nodeAuditSkipDevDependencies";
        /**
         * Disables the RetireJS Analyzer.
         */
        public static final String DISABLE_RETIRE_JS = "disableRetireJS";
        /**
         * Whether the RetireJS Analyzer will update regardless of the
         * `autoupdate` setting.
         */
        public static final String RETIRE_JS_FORCEUPDATE = "retireJsForceUpdate";
        /**
         * The URL to the retire JS repository.
         */
        public static final String RETIREJS_URL = "retireJsUrl";
        /**
         * The username to the retire JS repository.
         */
        public static final String RETIREJS_URL_USER = "retireJsUrlUser";
        /**
         * The password to the retire JS repository.
         */
        public static final String RETIREJS_URL_PASSWORD = "retireJsUrlPass";
        /**
         * The URL of the nexus server.
         */
        public static final String NEXUS_URL = "nexus";
        /**
         * The username for the nexus server.
         */
        public static final String NEXUS_USERNAME = "nexusUser";
        /**
         * The password for the nexus server.
         */
        public static final String NEXUS_PASSWORD = "nexusPass";
        /**
         * Whether or not the defined proxy should be used when connecting to
         * Nexus.
         */
        public static final String NEXUS_USES_PROXY = "nexusUsesProxy";
        /**
         * The CLI argument name for setting the connection string.
         */
        public static final String CONNECTION_STRING = "connectionString";
        /**
         * The CLI argument name for setting the database user name.
         */
        public static final String DB_NAME = "dbUser";
        /**
         * The CLI argument name for setting the database password.
         */
        public static final String DB_PASSWORD = "dbPassword";
        /**
         * The CLI argument name for setting the database driver name.
         */
        public static final String DB_DRIVER = "dbDriverName";
        /**
         * The CLI argument name for setting the path to the database driver; in
         * case it is not on the class path.
         */
        public static final String DB_DRIVER_PATH = "dbDriverPath";
        /**
         * The CLI argument name for setting the path to dotnet core.
         */
        public static final String PATH_TO_CORE = "dotnet";
        /**
         * The CLI argument name for setting extra extensions.
         */
        public static final String ADDITIONAL_ZIP_EXTENSIONS = "zipExtensions";
        /**
         * Exclude path argument.
         */
        public static final String EXCLUDE = "exclude";
        /**
         * The CLI argument name for setting the path to bundle-audit for Ruby
         * bundle analysis.
         */
        public static final String PATH_TO_BUNDLE_AUDIT = "bundleAudit";
        /**
         * The CLI argument name for setting the path that should be used as the
         * working directory that the bundle-audit command used for Ruby bundle
         * analysis should be executed from. This will allow for the usage of
         * rbenv
         */
        public static final String PATH_TO_BUNDLE_AUDIT_WORKING_DIRECTORY = "bundleAuditWorkingDirectory";
        /**
         * The CLI argument name for setting the path to mix_audit for Elixir
         * analysis.
         */
        public static final String PATH_TO_MIX_AUDIT = "mixAudit";
        /**
         * The CLI argument to enable the experimental analyzers.
         */
        public static final String EXPERIMENTAL = "enableExperimental";
        /**
         * The CLI argument to enable the retired analyzers.
         */
        public static final String RETIRED = "enableRetired";
        /**
         * The CLI argument for the retire js content filters.
         */
        public static final String RETIREJS_FILTERS = "retirejsFilter";
        /**
         * The CLI argument for the retire js content filters.
         */
        public static final String RETIREJS_FILTER_NON_VULNERABLE = "retirejsFilterNonVulnerable";
        /**
         * The CLI argument for indicating if the Artifactory analyzer should be
         * enabled.
         */
        public static final String ARTIFACTORY_ENABLED = "enableArtifactory";
        /**
         * The CLI argument for indicating if the Artifactory analyzer should
         * use the proxy.
         */
        public static final String ARTIFACTORY_URL = "artifactoryUrl";
        /**
         * The CLI argument for indicating the Artifactory username.
         */
        public static final String ARTIFACTORY_USERNAME = "artifactoryUsername";
        /**
         * The CLI argument for indicating the Artifactory API token.
         */
        public static final String ARTIFACTORY_API_TOKEN = "artifactoryApiToken";
        /**
         * The CLI argument for indicating the Artifactory bearer token.
         */
        public static final String ARTIFACTORY_BEARER_TOKEN = "artifactoryBearerToken";
        /**
         * The CLI argument for indicating if the Artifactory analyzer should
         * use the proxy.
         */
        public static final String ARTIFACTORY_USES_PROXY = "artifactoryUseProxy";
        /**
         * The CLI argument for indicating if the Artifactory analyzer should
         * use the parallel analysis.
         */
        public static final String ARTIFACTORY_PARALLEL_ANALYSIS = "artifactoryParallelAnalysis";
        /**
         * The CLI argument to configure when the execution should be considered
         * a failure.
         */
        public static final String FAIL_ON_CVSS = "failOnCVSS";
        /**
         * The CLI argument to configure if the XML and JSON reports should be
         * pretty printed.
         */
        public static final String PRETTY_PRINT = "prettyPrint";
        /**
         * The CLI argument to set the threshold that is considered a failure
         * when generating the JUNIT report format.
         */
        public static final String FAIL_JUNIT_ON_CVSS = "junitFailOnCVSS";
        /**
         * The CLI argument to set the number of hours to wait before
         * re-checking hosted suppressions file for updates.
         */
        public static final String DISABLE_HOSTED_SUPPRESSIONS = "disableHostedSuppressions";
        /**
         * The CLI argument to set the number of hours to wait before
         * re-checking hosted suppressions file for updates.
         */
        public static final String HOSTED_SUPPRESSIONS_VALID_FOR_HOURS = "hostedSuppressionsValidForHours";
        /**
         * The CLI argument to set Whether the hosted suppressions file will
         * update regardless of the `noupdate` argument.
         */
        public static final String HOSTED_SUPPRESSIONS_FORCEUPDATE = "hostedSuppressionsForceUpdate";
        /**
         * The CLI argument to set the location of a mirrored hosted
         * suppressions file .
         */
        public static final String HOSTED_SUPPRESSIONS_URL = "hostedSuppressionsUrl";
    }
}
