/*
 * This file is part of dependency-check-cli.
 *
 * Dependency-check-cli is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-cli is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-cli. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.cli;

import java.io.File;
import java.io.FileNotFoundException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.owasp.dependencycheck.reporting.ReportGenerator.Format;
import org.owasp.dependencycheck.utils.Settings;

/**
 * A utility to parse command line arguments for the DependencyCheck.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class CliParser {

    /**
     * The command line.
     */
    private CommandLine line;
    /**
     * The options for the command line parser.
     */
    private final Options options = createCommandLineOptions();
    /**
     * Indicates whether the arguments are valid.
     */
    private boolean isValid = true;

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
        final CommandLineParser parser = new PosixParser();
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
        if (isRunScan()) {
            validatePathExists(getScanFiles(), "scan");
            validatePathExists(getReportDirectory(), "out");
            if (!line.hasOption(ArgumentName.APP_NAME)) {
                throw new ParseException("Missing 'app' argument; the scan cannot be run without the an application name.");
            }
            if (line.hasOption(ArgumentName.OUTPUT_FORMAT)) {
                final String format = line.getOptionValue(ArgumentName.OUTPUT_FORMAT);
                try {
                    Format.valueOf(format);
                } catch (IllegalArgumentException ex) {
                    final String msg = String.format("An invalid 'format' of '%s' was specified. Supported output formats are XML, HTML, VULN, or ALL", format);
                    throw new ParseException(msg);
                }
            }
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
     * @param optType the option being validated (e.g. scan, out, etc.)
     * @throws FileNotFoundException is thrown if the path being validated does
     * not exist.
     */
    private void validatePathExists(String path, String optType) throws FileNotFoundException {
        final File f = new File(path);
        if (!f.exists()) {
            isValid = false;
            final String msg = String.format("Invalid '%s' argument: '%s'", optType, path);
            throw new FileNotFoundException(msg);
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
        final Option help = new Option(ArgumentName.HELP_SHORT, ArgumentName.HELP, false,
                "Print this message.");

        final Option version = new Option(ArgumentName.VERSION_SHORT, ArgumentName.VERSION,
                false, "Print the version information.");

        final Option noUpdate = new Option(ArgumentName.DISABLE_AUTO_UPDATE_SHORT, ArgumentName.DISABLE_AUTO_UPDATE,
                false, "Disables the automatic updating of the CPE data.");

        final Option appName = OptionBuilder.withArgName("name").hasArg().withLongOpt(ArgumentName.APP_NAME)
                .withDescription("The name of the application being scanned. This is a required argument.")
                .create(ArgumentName.APP_NAME_SHORT);

        final Option connectionTimeout = OptionBuilder.withArgName("timeout").hasArg().withLongOpt(ArgumentName.CONNECTION_TIMEOUT)
                .withDescription("The connection timeout (in milliseconds) to use when downloading resources.")
                .create(ArgumentName.CONNECTION_TIMEOUT_SHORT);

        final Option proxyUrl = OptionBuilder.withArgName("url").hasArg().withLongOpt(ArgumentName.PROXY_URL)
                .withDescription("The proxy url to use when downloading resources.")
                .create(ArgumentName.PROXY_URL_SHORT);

        final Option proxyPort = OptionBuilder.withArgName("port").hasArg().withLongOpt(ArgumentName.PROXY_PORT)
                .withDescription("The proxy port to use when downloading resources.")
                .create(ArgumentName.PROXY_PORT_SHORT);

        final Option proxyUsername = OptionBuilder.withArgName("user").hasArg().withLongOpt(ArgumentName.PROXY_USERNAME)
                .withDescription("The proxy username to use when downloading resources.")
                .create(ArgumentName.PROXY_USERNAME_SHORT);

        final Option proxyPassword = OptionBuilder.withArgName("pass").hasArg().withLongOpt(ArgumentName.PROXY_PASSWORD)
                .withDescription("The proxy password to use when downloading resources.")
                .create(ArgumentName.PROXY_PASSWORD_SHORT);

        final Option path = OptionBuilder.withArgName("path").hasArg().withLongOpt(ArgumentName.SCAN)
                .withDescription("The path to scan - this option can be specified multiple times.")
                .create(ArgumentName.SCAN_SHORT);

        final Option props = OptionBuilder.withArgName("file").hasArg().withLongOpt(ArgumentName.PROP)
                .withDescription("A property file to load.")
                .create(ArgumentName.PROP_SHORT);

        final Option data = OptionBuilder.withArgName("path").hasArg().withLongOpt(ArgumentName.DATA_DIRECTORY)
                .withDescription("The location of the data directory used to store persistent data. This option should generally not be set.")
                .create(ArgumentName.DATA_DIRECTORY_SHORT);

        final Option out = OptionBuilder.withArgName("folder").hasArg().withLongOpt(ArgumentName.OUT)
                .withDescription("The folder to write reports to. This defaults to the current directory.")
                .create(ArgumentName.OUT_SHORT);

        final Option outputFormat = OptionBuilder.withArgName("format").hasArg().withLongOpt(ArgumentName.OUTPUT_FORMAT)
                .withDescription("The output format to write to (XML, HTML, VULN, ALL). The default is HTML.")
                .create(ArgumentName.OUTPUT_FORMAT_SHORT);

        final Option verboseLog = OptionBuilder.withArgName("file").hasArg().withLongOpt(ArgumentName.VERBOSE_LOG)
                .withDescription("The file path to write verbose logging information.")
                .create(ArgumentName.VERBOSE_LOG_SHORT);

        final Option suppressionFile = OptionBuilder.withArgName("file").hasArg().withLongOpt(ArgumentName.SUPPRESION_FILE)
                .withDescription("The file path to the suppression XML file.")
                .create(ArgumentName.SUPPRESION_FILE_SHORT);


        final OptionGroup og = new OptionGroup();
        og.addOption(path);

        final Options opts = new Options();
        opts.addOptionGroup(og);
        opts.addOption(out);
        opts.addOption(outputFormat);
        opts.addOption(appName);
        opts.addOption(version);
        opts.addOption(help);
        opts.addOption(noUpdate);
        opts.addOption(props);
        opts.addOption(data);
        opts.addOption(verboseLog);
        opts.addOption(suppressionFile);
        opts.addOption(proxyPort);
        opts.addOption(proxyUrl);
        opts.addOption(proxyUsername);
        opts.addOption(proxyPassword);
        opts.addOption(connectionTimeout);

        return opts;
    }

    /**
     * Determines if the 'version' command line argument was passed in.
     *
     * @return whether or not the 'version' command line argument was passed in
     */
    public boolean isGetVersion() {
        return (line != null) && line.hasOption(ArgumentName.VERSION);
    }

    /**
     * Determines if the 'help' command line argument was passed in.
     *
     * @return whether or not the 'help' command line argument was passed in
     */
    public boolean isGetHelp() {
        return (line != null) && line.hasOption(ArgumentName.HELP);
    }

    /**
     * Determines if the 'scan' command line argument was passed in.
     *
     * @return whether or not the 'scan' command line argument was passed in
     */
    public boolean isRunScan() {
        return (line != null) && isValid && line.hasOption(ArgumentName.SCAN);
    }

    /**
     * Displays the command line help message to the standard output.
     */
    public void printHelp() {
        final HelpFormatter formatter = new HelpFormatter();
        final String nl = System.getProperty("line.separator");

        formatter.printHelp(Settings.getString("application.name", "DependencyCheck"),
                nl + Settings.getString("application.name", "DependencyCheck")
                + " can be used to identify if there are any known CVE vulnerabilities in libraries utilized by an application. "
                + Settings.getString("application.name", "DependencyCheck")
                + " will automatically update required data from the Internet, such as the CVE and CPE data files from nvd.nist.gov." + nl + nl,
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
        return line.getOptionValues(ArgumentName.SCAN);
    }

    /**
     * Returns the directory to write the reports to specified on the command
     * line.
     *
     * @return the path to the reports directory.
     */
    public String getReportDirectory() {
        return line.getOptionValue(ArgumentName.OUT, ".");
    }

    /**
     * Returns the output format specified on the command line. Defaults to HTML
     * if no format was specified.
     *
     * @return the output format name.
     */
    public String getReportFormat() {
        return line.getOptionValue(ArgumentName.OUTPUT_FORMAT, "HTML");
    }

    /**
     * Returns the application name specified on the command line.
     *
     * @return the application name.
     */
    public String getApplicationName() {
        return line.getOptionValue(ArgumentName.APP_NAME);
    }

    /**
     * Returns the connection timeout.
     *
     * @return the connection timeout
     */
    public String getConnectionTimeout() {
        return line.getOptionValue(ArgumentName.CONNECTION_TIMEOUT);
    }

    /**
     * Returns the proxy url.
     *
     * @return the proxy url
     */
    public String getProxyUrl() {
        return line.getOptionValue(ArgumentName.PROXY_URL);
    }

    /**
     * Returns the proxy port.
     *
     * @return the proxy port
     */
    public String getProxyPort() {
        return line.getOptionValue(ArgumentName.PROXY_PORT);
    }

    /**
     * Returns the proxy username.
     *
     * @return the proxy username
     */
    public String getProxyUsername() {
        return line.getOptionValue(ArgumentName.PROXY_USERNAME);
    }

    /**
     * Returns the proxy password.
     *
     * @return the proxy password
     */
    public String getProxyPassword() {
        return line.getOptionValue(ArgumentName.PROXY_PASSWORD);
    }

    /**
     * Get the value of dataDirectory.
     *
     * @return the value of dataDirectory
     */
    public String getDataDirectory() {
        return line.getOptionValue(ArgumentName.DATA_DIRECTORY);
    }

    /**
     * Returns the properties file specified on the command line.
     *
     * @return the properties file specified on the command line
     */
    public File getPropertiesFile() {
        final String path = line.getOptionValue(ArgumentName.PROP);
        if (path != null) {
            return new File(path);
        }
        return null;
    }

    /**
     * Returns the path to the verbose log file.
     *
     * @return the path to the verbose log file
     */
    public String getVerboseLog() {
        return line.getOptionValue(ArgumentName.VERBOSE_LOG);
    }

    /**
     * Returns the path to the suppression file.
     *
     * @return the path to the suppression file
     */
    public String getSuppressionFile() {
        return line.getOptionValue(ArgumentName.SUPPRESION_FILE);
    }

    /**
     * <p>Prints the manifest information to standard output.</p>
     * <ul><li>Implementation-Title: ${pom.name}</li>
     * <li>Implementation-Version: ${pom.version}</li></ul>
     */
    public void printVersionInfo() {
        final String version = String.format("%s version %s",
                Settings.getString("application.name", "DependencyCheck"),
                Settings.getString("application.version", "Unknown"));
        System.out.println(version);
    }

    /**
     * Checks if the auto update feature has been disabled. If it has been
     * disabled via the command line this will return false.
     *
     * @return if auto-update is allowed.
     */
    public boolean isAutoUpdate() {
        return (line == null) || !line.hasOption(ArgumentName.DISABLE_AUTO_UPDATE);
    }

    /**
     * A collection of static final strings that represent the possible command
     * line arguments.
     */
    public static class ArgumentName {

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
         * The short CLI argument name specifying that the CPE/CVE/etc. data
         * should not be automatically updated.
         */
        public static final String DISABLE_AUTO_UPDATE_SHORT = "n";
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
         * The long CLI argument name specifying the name of the application to
         * be scanned.
         */
        public static final String APP_NAME = "app";
        /**
         * The short CLI argument name specifying the name of the application to
         * be scanned.
         */
        public static final String APP_NAME_SHORT = "a";
        /**
         * The long CLI argument name asking for help.
         */
        public static final String HELP = "help";
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
         * The short CLI argument name indicating the proxy port.
         */
        public static final String PROXY_PORT_SHORT = "p";
        /**
         * The CLI argument name indicating the proxy port.
         */
        public static final String PROXY_PORT = "proxyport";
        /**
         * The short CLI argument name indicating the proxy url.
         */
        public static final String PROXY_URL_SHORT = "u";
        /**
         * The CLI argument name indicating the proxy url.
         */
        public static final String PROXY_URL = "proxyurl";
        /**
         * The short CLI argument name indicating the proxy username.
         */
        public static final String PROXY_USERNAME_SHORT = "pu";
        /**
         * The CLI argument name indicating the proxy username.
         */
        public static final String PROXY_USERNAME = "proxyuser";
        /**
         * The short CLI argument name indicating the proxy password.
         */
        public static final String PROXY_PASSWORD_SHORT = "pp";
        /**
         * The CLI argument name indicating the proxy password.
         */
        public static final String PROXY_PASSWORD = "proxypass";
        /**
         * The short CLI argument name indicating the connection timeout.
         */
        public static final String CONNECTION_TIMEOUT_SHORT = "c";
        /**
         * The CLI argument name indicating the connection timeout.
         */
        public static final String CONNECTION_TIMEOUT = "connectiontimeout";
        /**
         * The short CLI argument name for setting the location of an additional
         * properties file.
         */
        public static final String PROP_SHORT = "p";
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
         * The CLI argument name for setting the location of the suppression
         * file.
         */
        public static final String SUPPRESION_FILE = "suppression";
        /**
         * The short CLI argument name for setting the location of the
         * suppression file.
         */
        public static final String SUPPRESION_FILE_SHORT = "sf";
    }
}
