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
package org.owasp.dependencycheck.reporting;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.text.WordUtils;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.context.Context;
import org.owasp.dependencycheck.analyzer.Analyzer;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.XmlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import javax.annotation.concurrent.NotThreadSafe;
import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.sax.SAXTransformerFactory;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * The ReportGenerator is used to, as the name implies, generate reports.
 * Internally the generator uses the Velocity Templating Engine. The
 * ReportGenerator exposes a list of Dependencies to the template when
 * generating the report.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class ReportGenerator {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ReportGenerator.class);

    /**
     * An enumeration of the report formats.
     */
    public enum Format {

        /**
         * Generate all reports.
         */
        ALL,
        /**
         * Generate XML report.
         */
        XML,
        /**
         * Generate HTML report.
         */
        HTML,
        /**
         * Generate JSON report.
         */
        JSON,
        /**
         * Generate CSV report.
         */
        CSV,
        /**
         * Generate Sarif report.
         */
        SARIF,
        /**
         * Generate HTML report without script or non-vulnerable libraries for
         * Jenkins.
         */
        JENKINS,
        /**
         * Generate JUNIT report.
         */
        JUNIT,
        /**
         * Generate Report in GitLab dependency check format.
         *
         * @see <a href="https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/dependency-scanning-report-format.json">format definition</a>
         * @see <a href="https://docs.gitlab.com/ee/development/integrations/secure.html">additional explanations on the format</a>
         */
        GITLAB
    }

    /**
     * The Velocity Engine.
     */
    private final VelocityEngine velocityEngine;
    /**
     * The Velocity Engine Context.
     */
    private final Context context;
    /**
     * The configured settings.
     */
    private final Settings settings;

    //CSOFF: ParameterNumber
    //CSOFF: LineLength

    /**
     * Constructs a new ReportGenerator.
     *
     * @param applicationName the application name being analyzed
     * @param dependencies the list of dependencies
     * @param analyzers the list of analyzers used
     * @param properties the database properties (containing timestamps of the
     * NVD CVE data)
     * @param settings a reference to the database settings
     * @deprecated Please use
     * {@link #ReportGenerator(java.lang.String, java.util.List, java.util.List, DatabaseProperties, Settings, ExceptionCollection)}
     */
    @Deprecated
    public ReportGenerator(String applicationName, List<Dependency> dependencies, List<Analyzer> analyzers,
                           DatabaseProperties properties, Settings settings) {
        this(applicationName, dependencies, analyzers, properties, settings, null);
    }

    /**
     * Constructs a new ReportGenerator.
     *
     * @param applicationName the application name being analyzed
     * @param dependencies the list of dependencies
     * @param analyzers the list of analyzers used
     * @param properties the database properties (containing timestamps of the
     * NVD CVE data)
     * @param settings a reference to the database settings
     * @param exceptions a collection of exceptions that may have occurred
     * during the analysis
     * @since 5.1.0
     */
    public ReportGenerator(String applicationName, List<Dependency> dependencies, List<Analyzer> analyzers,
                           DatabaseProperties properties, Settings settings, ExceptionCollection exceptions) {
        this(applicationName, null, null, null, dependencies, analyzers, properties, settings, exceptions);
    }

    /**
     * Constructs a new ReportGenerator.
     *
     * @param applicationName the application name being analyzed
     * @param groupID the group id of the project being analyzed
     * @param artifactID the application id of the project being analyzed
     * @param version the application version of the project being analyzed
     * @param dependencies the list of dependencies
     * @param analyzers the list of analyzers used
     * @param properties the database properties (containing timestamps of the
     * NVD CVE data)
     * @param settings a reference to the database settings
     * @deprecated Please use
     * {@link #ReportGenerator(String, String, String, String, List, List, DatabaseProperties, Settings, ExceptionCollection)}
     */
    @Deprecated
    public ReportGenerator(String applicationName, String groupID, String artifactID, String version,
                           List<Dependency> dependencies, List<Analyzer> analyzers, DatabaseProperties properties,
                           Settings settings) {
        this(applicationName, groupID, artifactID, version, dependencies, analyzers, properties, settings, null);
    }

    /**
     * Constructs a new ReportGenerator.
     *
     * @param applicationName the application name being analyzed
     * @param groupID the group id of the project being analyzed
     * @param artifactID the application id of the project being analyzed
     * @param version the application version of the project being analyzed
     * @param dependencies the list of dependencies
     * @param analyzers the list of analyzers used
     * @param properties the database properties (containing timestamps of the
     * NVD CVE data)
     * @param settings a reference to the database settings
     * @param exceptions a collection of exceptions that may have occurred
     * during the analysis
     * @since 5.1.0
     */
    public ReportGenerator(String applicationName, String groupID, String artifactID, String version,
                           List<Dependency> dependencies, List<Analyzer> analyzers, DatabaseProperties properties,
                           Settings settings, ExceptionCollection exceptions) {
        this.settings = settings;
        velocityEngine = createVelocityEngine();
        velocityEngine.init();
        context = createContext(applicationName, dependencies, analyzers, properties, groupID,
                artifactID, version, exceptions);
    }

    /**
     * Constructs the velocity context used to generate the dependency-check
     * reports.
     *
     * @param applicationName the application name being analyzed
     * @param groupID the group id of the project being analyzed
     * @param artifactID the application id of the project being analyzed
     * @param version the application version of the project being analyzed
     * @param dependencies the list of dependencies
     * @param analyzers the list of analyzers used
     * @param properties the database properties (containing timestamps of the
     * NVD CVE data)
     * @param exceptions a collection of exceptions that may have occurred
     * during the analysis
     * @return the velocity context
     */
    @SuppressWarnings("JavaTimeDefaultTimeZone")
    private VelocityContext createContext(String applicationName, List<Dependency> dependencies,
                                          List<Analyzer> analyzers, DatabaseProperties properties, String groupID,
                                          String artifactID, String version, ExceptionCollection exceptions) {

        final ZonedDateTime dt = ZonedDateTime.now();
        final String scanDate = DateTimeFormatter.RFC_1123_DATE_TIME.format(dt);
        final String scanDateXML = DateTimeFormatter.ISO_INSTANT.format(dt);
        final String scanDateJunit = DateTimeFormatter.ISO_LOCAL_DATE_TIME.format(dt);
        final String scanDateGitLab = DateTimeFormatter.ISO_LOCAL_DATE_TIME.format(dt.withNano(0));

        final VelocityContext ctxt = new VelocityContext();
        ctxt.put("applicationName", applicationName);
        dependencies.sort(Dependency.NAME_COMPARATOR);
        ctxt.put("dependencies", dependencies);
        ctxt.put("analyzers", analyzers);
        ctxt.put("properties", properties);
        ctxt.put("scanDate", scanDate);
        ctxt.put("scanDateXML", scanDateXML);
        ctxt.put("scanDateJunit", scanDateJunit);
        ctxt.put("scanDateGitLab", scanDateGitLab);
        ctxt.put("enc", new EscapeTool());
        ctxt.put("rpt", new ReportTool());
        ctxt.put("checksum", Checksum.class);
        ctxt.put("WordUtils", new WordUtils());
        ctxt.put("VENDOR", EvidenceType.VENDOR);
        ctxt.put("PRODUCT", EvidenceType.PRODUCT);
        ctxt.put("VERSION", EvidenceType.VERSION);
        ctxt.put("version", settings.getString(Settings.KEYS.APPLICATION_VERSION, "Unknown"));
        ctxt.put("settings", settings);
        if (version != null) {
            ctxt.put("applicationVersion", version);
        }
        if (artifactID != null) {
            ctxt.put("artifactID", artifactID);
        }
        if (groupID != null) {
            ctxt.put("groupID", groupID);
        }
        if (exceptions != null) {
            ctxt.put("exceptions", exceptions.getExceptions());
        }
        return ctxt;
    }
    //CSON: ParameterNumber
    //CSON: LineLength

    /**
     * Creates a new Velocity Engine.
     *
     * @return a velocity engine
     */
    private VelocityEngine createVelocityEngine() {
        return new VelocityEngine();
    }

    /**
     * Writes the dependency-check report to the given output location.
     *
     * @param outputLocation the path where the reports should be written
     * @param format the format the report should be written in (a valid member
     * of {@link Format}) or even the path to a custom velocity template
     * (either fully qualified or the template name on the class path).
     * @throws ReportException is thrown if there is an error creating out the
     * reports
     */
    public void write(String outputLocation, String format) throws ReportException {
        Format reportFormat = null;
        try {
            reportFormat = Format.valueOf(format.toUpperCase());
        } catch (IllegalArgumentException ex) {
            LOGGER.trace("ignore this exception", ex);
        }

        if (reportFormat != null) {
            write(outputLocation, reportFormat);
        } else {
            File out = getReportFile(outputLocation, null);
            if (out.isDirectory()) {
                out = new File(out, FilenameUtils.getBaseName(format));
                LOGGER.warn("Writing non-standard VSL output to a directory using template name as file name.");
            }
            LOGGER.info("Writing custom report to: {}", out.getAbsolutePath());
            processTemplate(format, out);
        }

    }

    /**
     * Writes the dependency-check report(s).
     *
     * @param outputLocation the path where the reports should be written
     * @param format the format the report should be written in (see
     * {@link Format})
     * @throws ReportException is thrown if there is an error creating out the
     * reports
     */
    public void write(String outputLocation, Format format) throws ReportException {
        if (format == Format.ALL) {
            for (Format f : Format.values()) {
                if (f != Format.ALL) {
                    write(outputLocation, f);
                }
            }
        } else {
            final File out = getReportFile(outputLocation, format);
            final String templateName = format.toString().toLowerCase() + "Report";
            LOGGER.info("Writing {} report to: {}", format, out.getAbsolutePath());
            processTemplate(templateName, out);
            if (settings.getBoolean(Settings.KEYS.PRETTY_PRINT, false)) {
                if (format == Format.JSON || format == Format.SARIF) {
                    pretifyJson(out.getPath());
                } else if (format == Format.XML || format == Format.JUNIT) {
                    pretifyXml(out.getPath());
                }
            }
        }
    }

    /**
     * Determines the report file name based on the give output location and
     * format. If the output location contains a full file name that has the
     * correct extension for the given report type then the output location is
     * returned. However, if the output location is a directory, this method
     * will generate the correct name for the given output format.
     *
     * @param outputLocation the specified output location
     * @param format the report format
     * @return the report File
     */
    public static File getReportFile(String outputLocation, Format format) {
        File outFile = new File(outputLocation);
        if (outFile.getParentFile() == null) {
            outFile = new File(".", outputLocation);
        }
        final String pathToCheck = outputLocation.toLowerCase();
        if (format == Format.XML && !pathToCheck.endsWith(".xml")) {
            return new File(outFile, "dependency-check-report.xml");
        }
        if (format == Format.HTML && !pathToCheck.endsWith(".html") && !pathToCheck.endsWith(".htm")) {
            return new File(outFile, "dependency-check-report.html");
        }
        if (format == Format.JENKINS && !pathToCheck.endsWith(".html") && !pathToCheck.endsWith(".htm")) {
            return new File(outFile, "dependency-check-jenkins.html");
        }
        if (format == Format.JSON && !pathToCheck.endsWith(".json")) {
            return new File(outFile, "dependency-check-report.json");
        }
        if (format == Format.CSV && !pathToCheck.endsWith(".csv")) {
            return new File(outFile, "dependency-check-report.csv");
        }
        if (format == Format.JUNIT && !pathToCheck.endsWith(".xml")) {
            return new File(outFile, "dependency-check-junit.xml");
        }
        if (format == Format.SARIF && !pathToCheck.endsWith(".sarif")) {
            return new File(outFile, "dependency-check-report.sarif");
        }
        if (format == Format.GITLAB && !pathToCheck.endsWith(".json")) {
            return new File(outFile, "dependency-check-gitlab.json");
        }
        return outFile;
    }

    /**
     * Generates a report from a given Velocity Template. The template name
     * provided can be the name of a template contained in the jar file, such as
     * 'XmlReport' or 'HtmlReport', or the template name can be the path to a
     * template file.
     *
     * @param template the name of the template to load
     * @param file the output file to write the report to
     * @throws ReportException is thrown when the report cannot be generated
     */
    @SuppressFBWarnings(justification = "try with resources will clean up the output stream", value = {"OBL_UNSATISFIED_OBLIGATION"})
    protected void processTemplate(String template, File file) throws ReportException {
        ensureParentDirectoryExists(file);
        try (OutputStream output = new FileOutputStream(file)) {
            processTemplate(template, output);
        } catch (IOException ex) {
            throw new ReportException(String.format("Unable to write to file: %s", file), ex);
        }
    }

    /**
     * Generates a report from a given Velocity Template. The template name
     * provided can be the name of a template contained in the jar file, such as
     * 'XmlReport' or 'HtmlReport', or the template name can be the path to a
     * template file.
     *
     * @param templateName the name of the template to load
     * @param outputStream the OutputStream to write the report to
     * @throws ReportException is thrown when an exception occurs
     */
    protected void processTemplate(String templateName, OutputStream outputStream) throws ReportException {
        InputStream input = null;
        String logTag;
        final File f = new File(templateName);
        try {
            if (f.isFile()) {
                try {
                    logTag = templateName;
                    input = new FileInputStream(f);
                } catch (FileNotFoundException ex) {
                    throw new ReportException("Unable to locate template file: " + templateName, ex);
                }
            } else {
                logTag = "templates/" + templateName + ".vsl";
                input = FileUtils.getResourceAsStream(logTag);
            }
            if (input == null) {
                logTag = templateName;
                input = FileUtils.getResourceAsStream(templateName);
            }
            if (input == null) {
                throw new ReportException("Template file doesn't exist: " + logTag);
            }

            try (InputStreamReader reader = new InputStreamReader(input, StandardCharsets.UTF_8);
                 OutputStreamWriter writer = new OutputStreamWriter(outputStream, StandardCharsets.UTF_8)) {
                if (!velocityEngine.evaluate(context, writer, logTag, reader)) {
                    throw new ReportException("Failed to convert the template into html.");
                }
                writer.flush();
            } catch (UnsupportedEncodingException ex) {
                throw new ReportException("Unable to generate the report using UTF-8", ex);
            }
        } catch (IOException ex) {
            throw new ReportException("Unable to write the report", ex);
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException ex) {
                    LOGGER.trace("Error closing input", ex);
                }
            }
        }
    }

    /**
     * Validates that the given file's parent directory exists. If the directory
     * does not exist an attempt to create the necessary path is made; if that
     * fails a ReportException will be raised.
     *
     * @param file the file or directory directory
     * @throws ReportException thrown if the parent directory does not exist and
     * cannot be created
     */
    private void ensureParentDirectoryExists(File file) throws ReportException {
        if (!file.getParentFile().exists()) {
            final boolean created = file.getParentFile().mkdirs();
            if (!created) {
                final String msg = String.format("Unable to create directory '%s'.", file.getParentFile().getAbsolutePath());
                throw new ReportException(msg);
            }
        }
    }

    /**
     * Reformats the given XML file.
     *
     * @param path the path to the XML file to be reformatted
     * @throws ReportException thrown if the given JSON file is malformed
     */
    private void pretifyXml(String path) throws ReportException {
        final String outputPath = path + ".pretty";
        final File in = new File(path);
        final File out = new File(outputPath);
        try (OutputStream os = new FileOutputStream(out)) {
            final TransformerFactory transformerFactory = SAXTransformerFactory.newInstance();
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            final Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

            final SAXSource saxs = new SAXSource(new InputSource(path));
            final XMLReader saxReader = XmlUtils.buildSecureSaxParser().getXMLReader();

            saxs.setXMLReader(saxReader);
            transformer.transform(saxs, new StreamResult(new OutputStreamWriter(os, StandardCharsets.UTF_8)));
        } catch (ParserConfigurationException | TransformerConfigurationException ex) {
            LOGGER.debug("Configuration exception when pretty printing", ex);
            LOGGER.error("Unable to generate pretty report, caused by: {}", ex.getMessage());
        } catch (TransformerException | SAXException | IOException ex) {
            LOGGER.debug("Malformed XML?", ex);
            LOGGER.error("Unable to generate pretty report, caused by: {}", ex.getMessage());
        }
        if (out.isFile() && in.isFile() && in.delete()) {
            try {
                Thread.sleep(1000);
                Files.move(out.toPath(), in.toPath());
            } catch (IOException ex) {
                LOGGER.error("Unable to generate pretty report, caused by: {}", ex.getMessage());
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                LOGGER.error("Unable to generate pretty report, caused by: {}", ex.getMessage());
            }
        }
    }

    /**
     * Reformats the given JSON file.
     *
     * @param pathToJson the path to the JSON file to be reformatted
     * @throws ReportException thrown if the given JSON file is malformed
     */
    private void pretifyJson(String pathToJson) throws ReportException {
        LOGGER.debug("pretify json: {}", pathToJson);
        final String outputPath = pathToJson + ".pretty";
        final File in = new File(pathToJson);
        final File out = new File(outputPath);

        final JsonFactory factory = new JsonFactory();

        try (InputStream is = new FileInputStream(in); OutputStream os = new FileOutputStream(out)) {

            final JsonParser parser = factory.createParser(is);
            final JsonGenerator generator = factory.createGenerator(os);

            generator.useDefaultPrettyPrinter();

            while (parser.nextToken() != null) {
                generator.copyCurrentEvent(parser);
            }
            generator.flush();
        } catch (IOException ex) {
            LOGGER.debug("Malformed JSON?", ex);
            throw new ReportException("Unable to generate json report", ex);
        }
        if (out.isFile() && in.isFile() && in.delete()) {
            try {
                Thread.sleep(1000);
                Files.move(out.toPath(), in.toPath());
            } catch (IOException ex) {
                LOGGER.error("Unable to generate pretty report, caused by: {}", ex.getMessage());
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                LOGGER.error("Unable to generate pretty report, caused by: {}", ex.getMessage());
            }
        }
    }

}
