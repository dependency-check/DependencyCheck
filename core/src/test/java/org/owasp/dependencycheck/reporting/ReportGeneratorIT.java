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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import org.junit.Assert;

import org.junit.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.xml.sax.SAXException;
import static org.junit.Assert.fail;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.DownloadFailedException;

/**
 *
 * @author Jeremy Long
 */
public class ReportGeneratorIT extends BaseDBTestCase {

    /**
     * Generates an XML report containing known vulnerabilities and realistic
     * data and validates the generated XML document against the XSD.
     */
    @Test
    public void testGenerateReport() {
        File writeTo = new File("target/test-reports/Report.xml");
        File writeJsonTo = new File("target/test-reports/Report.json");
        File writeHtmlTo = new File("target/test-reports/Report.html");
        File writeJunitTo = new File("target/test-reports/junit.xml");
        File writeCsvTo = new File("target/test-reports/Report.csv");
        File writeSarifTo = new File("target/test-reports/Report.sarif");

        File suppressionFile = BaseTest.getResourceAsFile(this, "incorrectSuppressions.xml");
        Settings settings = getSettings();
        settings.setString(Settings.KEYS.SUPPRESSION_FILE, suppressionFile.getAbsolutePath());
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        settings.setBoolean(Settings.KEYS.PRETTY_PRINT, true);

        generateReport(settings, writeTo, writeJsonTo, writeHtmlTo, writeJunitTo, writeCsvTo, writeSarifTo, suppressionFile);        
    }

    /**
     * Generates an XML report containing known vulnerabilities and realistic
     * data and validates the generated XML document against the XSD.
     */
    @Test
    public void testGenerateNodeAuditReport() {
        File writeTo = new File("target/test-reports/nodeAudit/Report.xml");
        File writeJsonTo = new File("target/test-reports/nodeAudit/Report.json");
        File writeHtmlTo = new File("target/test-reports/nodeAudit/Report.html");
        File writeJunitTo = new File("target/test-reports/nodeAudit/junit.xml");
        File writeCsvTo = new File("target/test-reports/nodeAudit/Report.csv");
        File writeSarifTo = new File("target/test-reports/nodeAudit/Report.sarif");

        File suppressionFile = BaseTest.getResourceAsFile(this, "incorrectSuppressions.xml");
        Settings settings = getSettings();
        settings.setString(Settings.KEYS.SUPPRESSION_FILE, suppressionFile.getAbsolutePath());
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED, true);
        settings.setBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);

        generateReport(settings, writeTo, writeJsonTo, writeHtmlTo, writeJunitTo, writeCsvTo, writeSarifTo, suppressionFile);
    }


    /**
     * Generates an XML report containing known vulnerabilities and realistic
     * data and validates the generated XML document against the XSD.
     */
    @Test
    public void testGenerateRetireJsReport() {
        File writeTo = new File("target/test-reports/retireJS/Report.xml");
        File writeJsonTo = new File("target/test-reports/retireJS/Report.json");
        File writeHtmlTo = new File("target/test-reports/retireJS/Report.html");
        File writeJunitTo = new File("target/test-reports/retireJS/junit.xml");
        File writeCsvTo = new File("target/test-reports/retireJS/Report.csv");
        File writeSarifTo = new File("target/test-reports/retireJS/Report.sarif");

        File suppressionFile = BaseTest.getResourceAsFile(this, "incorrectSuppressions.xml");
        Settings settings = getSettings();
        settings.setString(Settings.KEYS.SUPPRESSION_FILE, suppressionFile.getAbsolutePath());
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
        settings.setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);

        generateReport(settings, writeTo, writeJsonTo, writeHtmlTo, writeJunitTo, writeCsvTo, writeSarifTo, suppressionFile);
    }
    /**
     * Generates an XML report containing known vulnerabilities and realistic
     * data and validates the generated XML document against the XSD.
     */
    @Test
    public void testGenerateNodePackageReport() {
        File writeTo = new File("target/test-reports/NodePackage/Report.xml");
        File writeJsonTo = new File("target/test-reports/NodePackage/Report.json");
        File writeHtmlTo = new File("target/test-reports/NodePackage/Report.html");
        File writeJunitTo = new File("target/test-reports/NodePackage/junit.xml");
        File writeCsvTo = new File("target/test-reports/NodePackage/Report.csv");
        File writeSarifTo = new File("target/test-reports/NodePackage/Report.sarif");

        File suppressionFile = BaseTest.getResourceAsFile(this, "incorrectSuppressions.xml");
        Settings settings = getSettings();
        settings.setString(Settings.KEYS.SUPPRESSION_FILE, suppressionFile.getAbsolutePath());
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED, true);
        settings.setBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED, true);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);

        generateReport(settings, writeTo, writeJsonTo, writeHtmlTo, writeJunitTo, writeCsvTo, writeSarifTo, suppressionFile);
    }


    public void generateReport(Settings settings, File writeTo, File writeJsonTo, File writeHtmlTo, File writeJunitTo, File writeCsvTo, File writeSarifTo, File suppressionFile){
        try {
            //first check parent folder
            createParentFolder(writeTo);
            createParentFolder(writeJsonTo);
            createParentFolder(writeHtmlTo);
            createParentFolder(writeJunitTo);
            createParentFolder(writeCsvTo);
            createParentFolder(writeSarifTo);

            File struts = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
            File war = BaseTest.getResourceAsFile(this, "war-4.0.war");
            File cfu = BaseTest.getResourceAsFile(this, "commons-fileupload-1.2.1.jar");
            
            //File axis = new File(this.getClass().getClassLoader().getResource("axis2-adb-1.4.1.jar").getPath());
            File axis = BaseTest.getResourceAsFile(this, "axis2-adb-1.4.1.jar");
            //File jetty = new File(this.getClass().getClassLoader().getResource("org.mortbay.jetty.jar").getPath());
            File jetty = BaseTest.getResourceAsFile(this, "org.mortbay.jetty.jar");

            File nodeTest = BaseTest.getResourceAsFile(this, "nodejs");
            int vulnCount;
            try (Engine engine = new Engine(settings)) {
                engine.scan(struts);
                engine.scan(war);
                engine.scan(cfu);
                engine.scan(axis);
                engine.scan(jetty);
                engine.scan(nodeTest);
                engine.analyzeDependencies();

                vulnCount = countVulns(engine.getDependencies());
                ExceptionCollection exceptions = new ExceptionCollection();
                exceptions.addException(new DownloadFailedException("test exception 1"));
                DownloadFailedException sub = new DownloadFailedException("test cause exception - nested");
                DownloadFailedException inner = new DownloadFailedException("Unable to download test file", sub.fillInStackTrace());
                UpdateException ex = new UpdateException("Test Exception 2", inner.fillInStackTrace());
                exceptions.addException(ex);
                engine.writeReports("Test Report", "org.owasp", "dependency-check-core", "1.4.8", writeTo, "XML", exceptions);
                engine.writeReports("Test Report", "org.owasp", "dependency-check-core", "1.4.8", writeJsonTo, "JSON", exceptions);
                engine.writeReports("Test Report", "org.owasp", "dependency-check-core", "1.4.8", writeHtmlTo, "HTML", exceptions);
                engine.writeReports("Test Report", "org.owasp", "dependency-check-core", "1.4.8", writeCsvTo, "CSV", exceptions);
                engine.writeReports("Test Report", "org.owasp", "dependency-check-core", "1.4.8", writeJunitTo, "JUNIT", exceptions);
                engine.writeReports("Test Report", "org.owasp", "dependency-check-core", "1.4.8", writeSarifTo, "SARIF", exceptions);
            }
            //Test XML
            InputStream xsdStream = ReportGenerator.class.getClassLoader().getResourceAsStream("schema/dependency-check.4.1.xsd");
            StreamSource xsdSource = new StreamSource(xsdStream);
            StreamSource xmlSource = new StreamSource(writeTo);
            SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = sf.newSchema(xsdSource);
            Validator validator = schema.newValidator();
            validator.validate(xmlSource);

            //Test CSV
            int linesWritten = countLines(writeCsvTo);
            Assert.assertEquals(vulnCount + 1, linesWritten);
        } catch (DatabaseException | ExceptionCollection | ReportException | SAXException | IOException ex) {
            fail(ex.getMessage());
        }
    }

    /**
     * create the parent folder if doesn't exist
     * @param file the file
     * @return true if all fine ?
     */
    private boolean createParentFolder(File file){
        if (!file.getParentFile().exists()) {
            return file.getParentFile().mkdir();
        }
        return true;
    }



    /**
     * Counts the lines in a file. Copied from
     * https://stackoverflow.com/a/14411695.
     *
     * @param file the file path
     * @return the count of the lines in the file
     * @throws IOException thrown if the file can't be read
     */
    private int countLines(File file) throws IOException {
        try (InputStream is = new BufferedInputStream(new FileInputStream(file))) {
            byte[] c = new byte[1024];
            int count = 0;
            int readChars = 0;
            boolean endsWithoutNewLine = false;
            while ((readChars = is.read(c)) != -1) {
                for (int i = 0; i < readChars; ++i) {
                    if (c[i] == '\n') {
                        ++count;
                    }
                }
                endsWithoutNewLine = (c[readChars - 1] != '\n');
            }
            if (endsWithoutNewLine) {
                ++count;
            }
            return count;
        }
    }

    private int countVulns(Dependency[] dependencies) {
        return Arrays.stream(dependencies)
                .mapToInt(d -> d.getVulnerabilities().size())
                .sum();
    }

}
