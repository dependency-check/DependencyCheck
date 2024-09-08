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
 * Copyright (c) 2018 Paul Irwin. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import java.io.File;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nuget.MSBuildProjectParseException;
import org.owasp.dependencycheck.data.nuget.NugetPackageReference;
import org.owasp.dependencycheck.data.nuget.XPathMSBuildProjectParser;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.Checksum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.apache.commons.io.input.BOMInputStream;

import static org.owasp.dependencycheck.analyzer.NuspecAnalyzer.DEPENDENCY_ECOSYSTEM;
import org.owasp.dependencycheck.data.nuget.DirectoryBuildPropsParser;
import org.owasp.dependencycheck.data.nuget.DirectoryPackagesPropsParser;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;

/**
 * Analyzes MS Project files for dependencies.
 *
 * @author Paul Irwin
 */
@ThreadSafe
public class MSBuildProjectAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NuspecAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "MSBuild Project Analyzer";

    /**
     * The phase in which the analyzer runs.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The types of files on which this will work.
     */
    private static final String[] SUPPORTED_EXTENSIONS = new String[]{"csproj", "vbproj"};

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(SUPPORTED_EXTENSIONS).build();
    /**
     * The import value to compare for GetDirectoryNameOfFileAbove.
     */
    private static final String IMPORT_GET_DIRECTORY = "$([MSBuild]::GetDirectoryNameOfFileAbove($(MSBuildThisFileDirectory)..,"
            + "Directory.Build.props))\\Directory.Build.props";
    /**
     * The import value to compare for GetPathOfFileAbove.
     */
    private static final String IMPORT_GET_PATH_OF_FILE = "$([MSBuild]::GetPathOfFileAbove('Directory.Build.props','"
            + "$(MSBuildThisFileDirectory)../'))";
    /**
     * The msbuild properties file name.
     */
    private static final String DIRECTORY_BUILDPROPS = "Directory.Build.props";
    /**
     * The nuget centrally managed props file.
     */
    private static final String DIRECTORY_PACKAGESPROPS = "Directory.Packages.props";

    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_MSBUILD_PROJECT_ENABLED;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        // intentionally left blank
    }

    @Override
    @SuppressWarnings("StringSplitter")
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        final File parent = dependency.getActualFile().getParentFile();

        try {
            //TODO while we are supporting props - we still do not support Directory.Build.targets
            final Properties props = loadDirectoryBuildProps(parent);

            final Map<String, String> centrallyManaged = loadCentrallyManaged(parent, props);

            LOGGER.debug("Checking MSBuild project file {}", dependency);

            final XPathMSBuildProjectParser parser = new XPathMSBuildProjectParser();
            final List<NugetPackageReference> packages;

            try (FileInputStream fis = new FileInputStream(dependency.getActualFilePath());
                    BOMInputStream bis = BOMInputStream.builder().setInputStream(fis).get()) {
                //skip BOM if it exists
                bis.getBOM();
                packages = parser.parse(bis, props, centrallyManaged);
            } catch (MSBuildProjectParseException | FileNotFoundException ex) {
                throw new AnalysisException(ex);
            }

            if (packages == null || packages.isEmpty()) {
                return;
            }

            for (NugetPackageReference npr : packages) {
                final Dependency child = new Dependency(dependency.getActualFile(), true);

                final String id = npr.getId();
                final String version = npr.getVersion();

                child.setEcosystem(DEPENDENCY_ECOSYSTEM);
                child.setName(id);
                child.setVersion(version);
                try {
                    final PackageURL purl = PackageURLBuilder.aPackageURL().withType("nuget").withName(id).withVersion(version).build();
                    child.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
                } catch (MalformedPackageURLException ex) {
                    LOGGER.debug("Unable to build package url for msbuild", ex);
                    final GenericIdentifier gid = new GenericIdentifier("msbuild:" + id + "@" + version, Confidence.HIGHEST);
                    child.addSoftwareIdentifier(gid);
                }
                child.setPackagePath(String.format("%s:%s", id, version));
                child.setSha1sum(Checksum.getSHA1Checksum(String.format("%s:%s", id, version)));
                child.setSha256sum(Checksum.getSHA256Checksum(String.format("%s:%s", id, version)));
                child.setMd5sum(Checksum.getMD5Checksum(String.format("%s:%s", id, version)));

                child.addEvidence(EvidenceType.PRODUCT, "msbuild", "id", id, Confidence.HIGHEST);
                child.addEvidence(EvidenceType.VERSION, "msbuild", "version", version, Confidence.HIGHEST);

                if (id.indexOf('.') > 0) {
                    final String[] parts = id.split("\\.");

                    // example: Microsoft.EntityFrameworkCore
                    child.addEvidence(EvidenceType.VENDOR, "msbuild", "id", parts[0], Confidence.MEDIUM);
                    child.addEvidence(EvidenceType.PRODUCT, "msbuild", "id", parts[1], Confidence.MEDIUM);

                    if (parts.length > 2) {
                        final String rest = id.substring(id.indexOf('.') + 1);
                        child.addEvidence(EvidenceType.PRODUCT, "msbuild", "id", rest, Confidence.MEDIUM);
                    }
                } else {
                    // example: jQuery
                    child.addEvidence(EvidenceType.VENDOR, "msbuild", "id", id, Confidence.LOW);
                }

                engine.addDependency(child);
            }

        } catch (Throwable e) {
            throw new AnalysisException(e);
        }
    }

    /**
     * Attempts to load the `Directory.Build.props` file.
     *
     * @param directory the project directory.
     * @return the properties from the Directory.Build.props.
     * @throws MSBuildProjectParseException thrown if there is an error parsing
     * the Directory.Build.props files.
     */
    private Properties loadDirectoryBuildProps(File directory) throws MSBuildProjectParseException {
        final Properties props = new Properties();
        if (directory == null || !directory.isDirectory()) {
            return props;
        }

        final File directoryProps = locateDirectoryBuildFile(DIRECTORY_BUILDPROPS, directory);
        if (directoryProps != null) {
            final Map<String, String> entries = readDirectoryBuildProps(directoryProps);

            if (entries != null) {
                for (Map.Entry<String, String> entry : entries.entrySet()) {
                    props.put(entry.getKey(), entry.getValue());
                }
            }
        }
        return props;
    }

    /**
     * Walk the current directory up to find `Directory.Build.props`.
     *
     * @param name the name of the build file to load.
     * @param directory the directory to begin searching at.
     * @return the `Directory.Build.props` file if found; otherwise null.
     */
    private File locateDirectoryBuildFile(String name, File directory) {
        File search = directory;
        while (search != null && search.isDirectory()) {
            final File props = new File(search, name);
            if (props.isFile()) {
                return props;
            }
            search = search.getParentFile();
        }
        return null;
    }

    /**
     * Exceedingly naive processing of MSBuild Import statements. Only four
     * cases are supported:
     * <ul>
     * <li>A relative path to the import</li>
     * <li>$(MSBuildThisFileDirectory)../path.to.props</li>
     * <li>$([MSBuild]::GetPathOfFileAbove('Directory.Build.props',
     * '$(MSBuildThisFileDirectory)../'))</li>
     * <li>$([MSBuild]::GetDirectoryNameOfFileAbove($(MSBuildThisFileDirectory)..,
     * Directory.Build.props))\Directory.Build.props</li>
     * </ul>
     *
     * @param importStatement the import statement
     * @param currentFile the props file containing the import
     * @return a reference to the file if it could be found, otherwise null.
     */
    private File getImport(String importStatement, File currentFile) {
        //<Import Project="$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '$(MSBuildThisFileDirectory)../'))" />
        //<Import Project="$([MSBuild]::GetDirectoryNameOfFileAbove($(MSBuildThisFileDirectory).., Directory.Build.props))\Directory.Build.props" />
        if (importStatement == null || importStatement.isEmpty()) {
            return null;
        }
        if (importStatement.startsWith("$")) {
            final String compact = importStatement.replaceAll("\\s", "");
            if (IMPORT_GET_PATH_OF_FILE.equalsIgnoreCase(compact)
                    || IMPORT_GET_DIRECTORY.equalsIgnoreCase(compact)) {
                return locateDirectoryBuildFile("Directory.Build.props", currentFile.getParentFile().getParentFile());
            } else if (importStatement.startsWith("$(MSBuildThisFileDirectory)")) {
                final String path = importStatement.substring(27);
                final File currentDirectory = currentFile.getParentFile();
                final Path p = Paths.get(currentDirectory.getAbsolutePath(),
                        path.replace('\\', File.separatorChar).replace('/', File.separatorChar));
                final File f = p.normalize().toFile();
                if (f.isFile() && !f.equals(currentFile)) {
                    return f;
                }
            }
        } else {
            final File currentDirectory = currentFile.getParentFile();
            final Path p = Paths.get(currentDirectory.getAbsolutePath(),
                    importStatement.replace('\\', File.separatorChar).replace('/', File.separatorChar));

            final File f = p.normalize().toFile();

            if (f.isFile() && !f.equals(currentFile)) {
                return f;
            }
        }
        LOGGER.warn("Unable to import Directory.Build.props import `{}` in `{}`", importStatement, currentFile);
        return null;
    }

    private Map<String, String> readDirectoryBuildProps(File directoryProps) throws MSBuildProjectParseException {
        Map<String, String> entries = null;
        final Set<String> imports = new HashSet<>();
        if (directoryProps != null && directoryProps.isFile()) {
            final DirectoryBuildPropsParser parser = new DirectoryBuildPropsParser();
            try (FileInputStream fis = new FileInputStream(directoryProps);
                    BOMInputStream bis = BOMInputStream.builder().setInputStream(fis).get()) {
                //skip BOM if it exists
                bis.getBOM();
                entries = parser.parse(bis);
                imports.addAll(parser.getImports());
            } catch (IOException ex) {
                throw new MSBuildProjectParseException("Error reading Directory.Build.props", ex);
            }

            for (String importStatement : imports) {
                final File parentBuildProps = getImport(importStatement, directoryProps);
                if (parentBuildProps != null && !directoryProps.equals(parentBuildProps)) {
                    final Map<String, String> parentEntries = readDirectoryBuildProps(parentBuildProps);
                    if (parentEntries != null) {
                        parentEntries.putAll(entries);
                        entries = parentEntries;
                    }
                }
            }
            return entries;
        }
        return null;
    }

    private Map<String, String> loadCentrallyManaged(File folder, Properties props) throws MSBuildProjectParseException {
        final File packages = locateDirectoryBuildFile(DIRECTORY_PACKAGESPROPS, folder);
        if (packages != null && packages.isFile()) {
            final DirectoryPackagesPropsParser parser = new DirectoryPackagesPropsParser();
            try (FileInputStream fis = new FileInputStream(packages);
                    BOMInputStream bis = BOMInputStream.builder().setInputStream(fis).get()) {
                //skip BOM if it exists
                bis.getBOM();
                return parser.parse(bis, props);
            } catch (IOException ex) {
                throw new MSBuildProjectParseException("Error reading Directory.Build.props", ex);
            }
        }
        return new HashMap<>();
    }

}
