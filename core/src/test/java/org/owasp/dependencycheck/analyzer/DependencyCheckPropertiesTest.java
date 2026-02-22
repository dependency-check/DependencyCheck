package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DependencyCheckPropertiesTest {

    @Test
    void should_each_analyzer_have_default_enabled_property()
            throws IOException, InstantiationException, IllegalAccessException {
        String packageName = "org.owasp.dependencycheck.analyzer";
        Set<Class<AbstractAnalyzer>> analyzerImplementations = findAllAnalyzerImplementations(packageName);

        Set<String> analyzerEnabledSettingKeys = new HashSet<>();

        for (Class<AbstractAnalyzer> analyzerClass : analyzerImplementations) {
            AbstractAnalyzer analyzer = analyzerClass.newInstance();
            String enabledKey = analyzer.getAnalyzerEnabledSettingKey();
            analyzerEnabledSettingKeys.add(enabledKey);
        }


        Properties properties = new Properties();
        Path propertiesPath = Paths.get("src", "main", "resources", "dependencycheck.properties");
        try (FileInputStream fis = new FileInputStream(propertiesPath.toFile())) {
            properties.load(fis);
        }

        assertFalse(analyzerEnabledSettingKeys.isEmpty());

        Set<String> absentKeys = analyzerEnabledSettingKeys.stream()
                .filter(key -> !properties.containsKey(key))
                .collect(Collectors.toSet());

        assertTrue(absentKeys.isEmpty());
    }

    private Set<Class<AbstractAnalyzer>> findAllAnalyzerImplementations(String packageName)
            throws IOException {

        Set<Class<?>> packageClasses = findAllClasses(packageName);

        Set<Class<AbstractAnalyzer>> analyzers = new HashSet<>();
        for (Class<?> clazz : packageClasses) {
            if (isAnalyzerImplementation(clazz)) {
                // We can safely cast due to call to isAnalyzerImplementation()
                @SuppressWarnings("unchecked")
                Class<AbstractAnalyzer> abstractAnalyzer = (Class<AbstractAnalyzer>) clazz;
                analyzers.add(abstractAnalyzer);
            }
        }

        return analyzers;
    }

    private boolean isAnalyzerImplementation(Class<?> clazz) {
        if (isAnAbstractClass(clazz) || isATestAnalyzer(clazz)) {
            return false;
        }

        return AbstractAnalyzer.class.isAssignableFrom(clazz);
    }

    private boolean isAnAbstractClass(Class<?> clazz) {
        return Modifier.isAbstract(clazz.getModifiers());
    }

    private boolean isATestAnalyzer(Class<?> clazz) {
        return clazz == AbstractSuppressionAnalyzerTest.AbstractSuppressionAnalyzerImpl.class;
    }

    private Set<Class<?>> findAllClasses(String packageName) throws IOException {
        String parsedPackageName = packageName.replaceAll("[.]", "/");

        Set<Class<?>> classes = new HashSet<>();
        Enumeration<URL> resources = ClassLoader.getSystemClassLoader().getResources(parsedPackageName);
        while (resources.hasMoreElements()) {
            URL resource = resources.nextElement();
            classes.addAll(getClasses(resource, packageName));
        }

        return classes;
    }

    private Set<Class<?>> getClasses(URL resource, String packageName) throws IOException {
        if (Objects.nonNull(resource)) {
            try (InputStream is = resource.openStream();
                 InputStreamReader isr = new InputStreamReader(is, StandardCharsets.UTF_8);
                 BufferedReader reader = new BufferedReader(isr)) {

                return tryGetClasses(packageName, reader);
            }
        }

        return Collections.emptySet();
    }

    private Set<Class<?>> tryGetClasses(String packageName, BufferedReader reader) {
        return reader.lines()
                .filter(line -> line.endsWith(".class"))
                .map(line -> getClass(line, packageName))
                .collect(Collectors.toSet());
    }

    private Class<?> getClass(String className, String packageName) {
        try {
            return tryGetClass(className, packageName);
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private Class<?> tryGetClass(String className, String packageName) throws ClassNotFoundException {
        return Class.forName(packageName + "." + className.substring(0, className.lastIndexOf('.')));
    }
}
