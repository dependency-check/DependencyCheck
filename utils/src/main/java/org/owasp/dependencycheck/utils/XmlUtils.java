/*
 * This file is part of dependency-check-utils.
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
 * Copyright (c) 2016 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import com.google.common.annotations.VisibleForTesting;
import org.jspecify.annotations.NonNull;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;

/**
 * Collection of XML related code.
 *
 * @author Jeremy Long
 * @version $Id: $Id
 */
public final class XmlUtils {

    /**
     * JAXP Schema Language. Source:
     * <a href="https://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html">...</a>
     */
    public static final String JAXP_SCHEMA_LANGUAGE = "http://java.sun.com/xml/jaxp/properties/schemaLanguage";
    /**
     * W3C XML Schema. Source:
     * <a href="https://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html">...</a>
     */
    public static final String W3C_XML_SCHEMA = "http://www.w3.org/2001/XMLSchema";
    /**
     * JAXP Schema Source. Source:
     * <a href="https://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html">...</a>
     */
    public static final String JAXP_SCHEMA_SOURCE = "http://java.sun.com/xml/jaxp/properties/schemaSource";

    /**
     * Private constructor for a utility class.
     */
    private XmlUtils() {
    }

    /**
     * Constructs a validating secure SAX XMLReader that can validate against schemas maintained locally.
     *
     * @param schemas One or more schemas with the schema(s) that the
     * parser should be able to validate the XML against, one InputSource per
     * schema
     * @return a validating SAX-based XML reader; pre-configured to validate against the locally passed schemas
     * @throws javax.xml.parsers.ParserConfigurationException is thrown if there
     * is a parser configuration exception
     * @throws org.xml.sax.SAXException is thrown if there is an issue setting SAX features
     * on the parser; or creating the parser
     */
    public static XMLReader buildSecureValidatingXmlReader(AutoCloseableInputSource... schemas) throws ParserConfigurationException,
            SAXException {
        final SAXParserFactory factory = buildSecureSaxParserFactory();

        factory.setNamespaceAware(true);
        factory.setValidating(true);

        final SAXParser saxParser = factory.newSAXParser();

        // Support validating from a set of schemas where we dont have schema locations set
        saxParser.setProperty(JAXP_SCHEMA_LANGUAGE, W3C_XML_SCHEMA);
        saxParser.setProperty(JAXP_SCHEMA_SOURCE, schemas);

        // Support validating where documents have schema location hints which we will intercept and load locally
        XMLReader xmlReader = saxParser.getXMLReader();
        xmlReader.setEntityResolver(new ExternalInterceptingEntityResolver(schemas));

        return xmlReader;
    }

    /**
     * Constructs a non-validating secure SAX XMLReader.
     *
     * @return a non-validating SAX-based XML reader
     * @throws javax.xml.parsers.ParserConfigurationException is thrown if there
     * is a parser configuration exception
     * @throws org.xml.sax.SAXException is thrown if there is an issue setting SAX features
     * on the parser; or creating the parser
     */
    public static XMLReader buildSecureXmlReader() throws ParserConfigurationException,
            SAXException {
        return buildSecureSaxParser().getXMLReader();
    }

    /**
     * Converts an attribute value representing an xsd:boolean value to a
     * boolean using the rules as stated in the XML specification.
     *
     * @param lexicalXSDBoolean The string-value of the boolean
     * @return the boolean value represented by {@code lexicalXSDBoolean}
     * @throws java.lang.IllegalArgumentException When {@code lexicalXSDBoolean}
     * does fit the lexical space of the XSD boolean datatype
     */
    public static boolean parseBoolean(String lexicalXSDBoolean) {
        final boolean result;
        switch (lexicalXSDBoolean) {
            case "true":
            case "1":
                result = true;
                break;
            case "false":
            case "0":
                result = false;
                break;
            default:
                throw new IllegalArgumentException("'" + lexicalXSDBoolean + "' is not a valid xs:boolean value");
        }
        return result;
    }

    /**
     * Constructs a secure non-validating SAX Parser.
     *
     * @return a SAX Parser
     * @throws javax.xml.parsers.ParserConfigurationException is thrown if there
     * is a parser configuration exception
     * @throws org.xml.sax.SAXException is thrown if there is an issue setting SAX features
     * on the parser; or creating the parser
     */
    public static SAXParser buildSecureSaxParser() throws ParserConfigurationException,
            SAXException {
        return buildSecureSaxParserFactory().newSAXParser();
    }

    private static @NonNull SAXParserFactory buildSecureSaxParserFactory() throws ParserConfigurationException, SAXNotRecognizedException, SAXNotSupportedException {
        final SAXParserFactory factory = SAXParserFactory.newInstance();

        // See https://xerces.apache.org/xerces2-j/features.html and
        // https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#jaxp-documentbuilderfactory-saxparserfactory-and-dom4j
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        // No doctypes, no DTDs (XSD only)
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

        // No XML Entity Expansion
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        return factory;
    }

    /**
     * Constructs a new document builder with security features enabled.
     *
     * @return a new document builder
     * @throws javax.xml.parsers.ParserConfigurationException thrown if there is
     * a parser configuration exception
     */
    public static DocumentBuilder buildSecureDocumentBuilder() throws ParserConfigurationException {
        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        return factory.newDocumentBuilder();
    }

    /**
     * Builds a prettier exception message.
     *
     * @param ex the SAXParseException
     * @return an easier to read exception message
     */
    public static String getPrettyParseExceptionInfo(SAXParseException ex) {

        final StringBuilder sb = new StringBuilder();

        if (ex.getSystemId() != null) {
            sb.append("systemId=").append(ex.getSystemId()).append(", ");
        }
        if (ex.getPublicId() != null) {
            sb.append("publicId=").append(ex.getPublicId()).append(", ");
        }
        if (ex.getLineNumber() > 0) {
            sb.append("Line=").append(ex.getLineNumber());
        }
        if (ex.getColumnNumber() > 0) {
            sb.append(", Column=").append(ex.getColumnNumber());
        }
        sb.append(": ").append(ex.getMessage());

        return sb.toString();
    }

    /**
     * Load HTTPS and file schema resources locally from the JAR files resources.
     */
    @VisibleForTesting
    static class ExternalInterceptingEntityResolver implements EntityResolver {
        private static final List<String> SCHEMA_LOCATION_PREFIXES_TO_INTERCEPT = List.of(
                // Canonical remote location for schemas published by Dependency-Check
                "https://dependency-check.github.io/DependencyCheck/",

                // Legacy remote location for schemas published by Dependency-Check
                "https://jeremylong.github.io/DependencyCheck/",

                // improper URIs, e.g "schema.xsd" will be assumed as file URIs relative to current working directory
                Path.of("").toUri().toString()
        );

        private final List<InputSource> inputSources;

        @VisibleForTesting
        ExternalInterceptingEntityResolver(InputSource[] inputSources) {
            this.inputSources = List.of(inputSources);
        }

        @Override
        public InputSource resolveEntity(String publicId, String systemId) {
           return Optional.ofNullable(systemId)
                   .map(this::toNormalizedResourceSystemId)
                   .flatMap(this::toKnownResourcePath)
                   .orElse(null);
        }

        private String toNormalizedResourceSystemId(String systemId) {
            return matchedPrefixFor(systemId).map(prefix -> systemId.substring(prefix.length())).orElse(systemId);
        }

        private Optional<String> matchedPrefixFor(String systemId) {
            return SCHEMA_LOCATION_PREFIXES_TO_INTERCEPT.stream().filter(systemId::startsWith).findFirst();
        }

        private Optional<InputSource> toKnownResourcePath(String resourceFilename) {
            return inputSources.stream().filter( s -> resourceFilename.equals(s.getSystemId())).findFirst();
        }
    }

}
