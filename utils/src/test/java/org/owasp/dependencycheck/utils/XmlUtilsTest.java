package org.owasp.dependencycheck.utils;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;

import javax.xml.parsers.ParserConfigurationException;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.owasp.dependencycheck.utils.AutoCloseableInputSource.fromResource;

class XmlUtilsTest {

    @BeforeAll
    static void validateSystemProperties() {
        assertEquals("", System.getProperty("javax.xml.accessExternalSchema", ""),
                "Tests expect access to external schema-validation to be disabled, as is the JVM default");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "schema-validation/simpledoc-valid-no-schemaloc.xml",
            "schema-validation/simpledoc-valid-schemaloc-https.xml",
            "schema-validation/simpledoc-valid-schemaloc-https-legacy.xml",
            "schema-validation/simpledoc-valid-schemaloc-ambiguous-uri.xml",
    })
    void shouldValidateXmlSuccessfullyAgainstSchema(String xmlToValidateResource) throws Exception {
        try (AutoCloseableInputSource simple = fromResource("schema-validation/simple.xsd");
             AutoCloseableInputSource irrelevant = fromResource("schema-validation/irrelevant.xsd");
             AutoCloseableInputSource toValidate = fromResource(xmlToValidateResource)) {

            withDefaultReader(simple, irrelevant).parse(toValidate);
        }
    }

    static Stream<Pair<String, String>> invalidSchemaDocProvider() {
        return Stream.of(
                Pair.of("schema-validation/simpledoc-invalid-schemaloc-https-badprefix.xml",
                        "'https' access is not allowed due to restriction set by the accessExternalSchema property"),
                Pair.of("schema-validation/simpledoc-invalid-schemaloc-https-notfound.xml",
                        "'https' access is not allowed due to restriction set by the accessExternalSchema property"),
                Pair.of("schema-validation/simpledoc-invalid-schemaloc-file.xml",
                        "'file' access is not allowed due to restriction set by the accessExternalSchema property"),
                Pair.of("schema-validation/simpledoc-invalid-schemaloc-ambiguous-uri.xml",
                        "'file' access is not allowed due to restriction set by the accessExternalSchema property.")
        );
    }

    @ParameterizedTest
    @MethodSource("invalidSchemaDocProvider")
    void shouldFailValidationWhenUnableToFindExternalSchema(Pair<String, String> test) throws Exception {
        try (AutoCloseableInputSource simple = fromResource("schema-validation/simple.xsd");
             AutoCloseableInputSource irrelevant = fromResource("schema-validation/irrelevant.xsd");
             AutoCloseableInputSource toValidate = fromResource(test.getLeft())) {

            Throwable t = assertThrows(SAXException.class, () -> withDefaultReader(simple, irrelevant).parse(toValidate));
            assertThat(t.getMessage(), containsString(test.getRight()));
        }
    }

    @Test
    void shouldFailValidationWhenDocIsInvalidForSchema() throws Exception {
        try (AutoCloseableInputSource simple = fromResource("schema-validation/simple.xsd");
             AutoCloseableInputSource irrelevant = fromResource("schema-validation/irrelevant.xsd");
             AutoCloseableInputSource toValidate = fromResource("schema-validation/simpledoc-invalid-no-schemaloc-bad-content.xml")) {

            Throwable t = assertThrows(SAXException.class, () -> withDefaultReader(simple, irrelevant).parse(toValidate));
            assertThat(t.getMessage(), containsString("Invalid content was found starting with element"));
        }
    }

    @Test
    void shouldFailValidationWhenNoRegisteredSchemas() throws Exception {
        try (AutoCloseableInputSource toValidate = fromResource("schema-validation/simpledoc-valid-no-schemaloc.xml")) {

            Throwable t = assertThrows(SAXException.class, () -> withDefaultReader().parse(toValidate));
            assertThat(t.getMessage(), containsString("Cannot find the declaration of element 'items'."));
        }
    }

    @Test
    void shouldFailValidationWhenNoRelevantSchemas() throws Exception {
        try (AutoCloseableInputSource irrelevant = fromResource("schema-validation/irrelevant.xsd");
             AutoCloseableInputSource toValidate = fromResource("schema-validation/simpledoc-valid-no-schemaloc.xml")) {

            Throwable t = assertThrows(SAXException.class, () -> withDefaultReader(irrelevant).parse(toValidate));
            assertThat(t.getMessage(), containsString("Cannot find the declaration of element 'items'."));
        }
    }

    private static @NotNull XMLReader withDefaultReader(AutoCloseableInputSource... schemas)
            throws ParserConfigurationException, SAXException {
        XMLReader xmlReader = XmlUtils.buildSecureValidatingXmlReader(schemas);
        xmlReader.setErrorHandler(new ErrorHandler() {
            @Override
            public void warning(SAXParseException exception) throws SAXException {
                throw exception;
            }

            @Override
            public void error(SAXParseException exception) throws SAXException {
                throw exception;
            }

            @Override
            public void fatalError(SAXParseException exception) throws SAXException {
                throw exception;
            }
        });
        return xmlReader;
    }

    @Nested
    public class ExternalInterceptingEntityResolverTest {

        @Test
        void shouldResolveKnownSchemaUsingCanonicalHttps() throws Exception {
            try (AutoCloseableInputSource simple = fromResource("schema-validation/simple.xsd")) {
                XmlUtils.ExternalInterceptingEntityResolver resolver = new XmlUtils.ExternalInterceptingEntityResolver(new InputSource[]{simple});
                InputSource resolved = resolver.resolveEntity(null, "https://dependency-check.github.io/DependencyCheck/simple.xsd");
                assertSame(simple, resolved);
            }
        }

        @Test
        void shouldResolveKnownSchemaUsingLegacyHttps() throws Exception {
            try (AutoCloseableInputSource simple = fromResource("schema-validation/simple.xsd")) {
                XmlUtils.ExternalInterceptingEntityResolver resolver = new XmlUtils.ExternalInterceptingEntityResolver(new InputSource[]{simple});
                InputSource resolved = resolver.resolveEntity(null, "https://jeremylong.github.io/DependencyCheck/simple.xsd");
                assertSame(simple, resolved);
            }
        }

        @Test
        void shouldResolveWhenSystemIdIsLocalFileName() throws Exception {
            try (AutoCloseableInputSource simple = fromResource("schema-validation/simple.xsd")) {
                XmlUtils.ExternalInterceptingEntityResolver resolver = new XmlUtils.ExternalInterceptingEntityResolver(new InputSource[]{simple});
                // systemId as just the filename should match the resource's systemId
                InputSource resolved = resolver.resolveEntity(null, "simple.xsd");
                assertSame(simple, resolved);
            }
        }

        @Test
        void shouldReturnNullForUnknownSystemId() throws Exception {
            try (AutoCloseableInputSource simple = fromResource("schema-validation/simple.xsd")) {
                XmlUtils.ExternalInterceptingEntityResolver resolver = new XmlUtils.ExternalInterceptingEntityResolver(new InputSource[]{simple});
                InputSource resolved = resolver.resolveEntity(null, "nonexistent.xsd");
                assertNull(resolved);
            }
        }

        @Test
        void shouldReturnNullWhenSystemIdIsNull() throws Exception {
            try (AutoCloseableInputSource simple = fromResource("schema-validation/simple.xsd")) {
                XmlUtils.ExternalInterceptingEntityResolver resolver = new XmlUtils.ExternalInterceptingEntityResolver(new InputSource[]{simple});
                InputSource resolved = resolver.resolveEntity(null, null);
                assertNull(resolved);
            }
        }
    }
}
