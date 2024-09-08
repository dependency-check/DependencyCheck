/*
 * This file is part of dependency-check-maven.
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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL.StandardTypes;
import com.github.packageurl.PackageURL;
import io.github.jeremylong.jcs3.slf4j.Slf4jAdapter;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.artifact.versioning.ArtifactVersion;
import org.apache.maven.doxia.sink.Sink;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.License;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.DefaultProjectBuildingRequest;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectBuildingRequest;
import org.apache.maven.reporting.MavenReport;
import org.apache.maven.reporting.MavenReportException;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Server;
import org.apache.maven.shared.transfer.artifact.DefaultArtifactCoordinate;
import org.apache.maven.shared.transfer.artifact.resolve.ArtifactResolver;
import org.apache.maven.shared.transfer.artifact.resolve.ArtifactResolverException;
import org.apache.maven.shared.transfer.artifact.resolve.ArtifactResult;
import org.apache.maven.shared.transfer.dependencies.resolve.DependencyResolver;
import org.apache.maven.shared.transfer.dependencies.resolve.DependencyResolverException;
import org.eclipse.aether.artifact.ArtifactType;
import org.apache.maven.shared.artifact.filter.PatternExcludesArtifactFilter;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilder;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilderException;
import org.apache.maven.shared.dependency.graph.DependencyNode;
import org.apache.maven.shared.dependency.graph.filter.ArtifactDependencyNodeFilter;
import org.apache.maven.shared.dependency.graph.internal.DefaultDependencyNode;
import org.apache.maven.shared.model.fileset.FileSet;
import org.apache.maven.shared.model.fileset.util.FileSetManager;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.exception.DependencyNotFoundException;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.Filter;
import org.owasp.dependencycheck.utils.Settings;
import org.sonatype.plexus.components.sec.dispatcher.DefaultSecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.artifact.repository.ArtifactRepository;

import org.apache.maven.artifact.resolver.filter.ExcludesArtifactFilter;
import org.apache.maven.artifact.versioning.InvalidVersionSpecificationException;
import org.apache.maven.artifact.versioning.Restriction;
import org.apache.maven.artifact.versioning.VersionRange;

import org.owasp.dependencycheck.agent.DependencyCheckScanAgent;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.apache.maven.shared.dependency.graph.traversal.DependencyNodeVisitor;
import org.apache.maven.shared.dependency.graph.traversal.FilteringDependencyNodeVisitor;
import org.apache.maven.shared.transfer.dependencies.DefaultDependableCoordinate;
import org.apache.maven.shared.transfer.dependencies.DependableCoordinate;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.SeverityUtil;
import org.owasp.dependencycheck.xml.pom.Model;
import org.owasp.dependencycheck.xml.pom.PomUtils;

//CSOFF: FileLength
/**
 * @author Jeremy Long
 */
public abstract class BaseDependencyCheckMojo extends AbstractMojo implements MavenReport {

    //<editor-fold defaultstate="collapsed" desc="Private fields">
    /**
     * The properties file location.
     */
    private static final String PROPERTIES_FILE = "mojo.properties";
    /**
     * System specific new line character.
     */
    private static final String NEW_LINE = System.getProperty("line.separator", "\n").intern();
    /**
     * Pattern to include all files in a FileSet.
     */
    private static final String INCLUDE_ALL = "**/*";
    /**
     * A flag indicating whether or not the Maven site is being generated.
     */
    private boolean generatingSite = false;
    /**
     * The configured settings.
     */
    private Settings settings = null;
    /**
     * The list of files that have been scanned.
     */
    private final List<File> scannedFiles = new ArrayList<>();
    //</editor-fold>
    // <editor-fold defaultstate="collapsed" desc="Maven bound parameters and components">
    /**
     * Sets whether or not the mojo should fail if an error occurs.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "failOnError", defaultValue = "true", required = true)
    private boolean failOnError;

    /**
     * The Maven Project Object.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "project", required = true, readonly = true)
    private MavenProject project;
    /**
     * List of Maven project of the current build
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(readonly = true, required = true, property = "reactorProjects")
    private List<MavenProject> reactorProjects;
    /**
     * The entry point towards a Maven version independent way of resolving
     * artifacts (handles both Maven 3.0 Sonatype and Maven 3.1+ eclipse Aether
     * implementations).
     */
    @SuppressWarnings("CanBeFinal")
    @Component
    private ArtifactResolver artifactResolver;
    /**
     * The entry point towards a Maven version independent way of resolving
     * dependencies (handles both Maven 3.0 Sonatype and Maven 3.1+ eclipse
     * Aether implementations). Contrary to the ArtifactResolver this resolver
     * also takes into account the additional repositories defined in the
     * dependency-path towards transitive dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Component
    private DependencyResolver dependencyResolver;

    /**
     * The Maven Session.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(defaultValue = "${session}", readonly = true, required = true)
    private MavenSession session;

    /**
     * Component within Maven to build the dependency graph.
     */
    @Component
    private DependencyGraphBuilder dependencyGraphBuilder;

    /**
     * The output directory. This generally maps to "target".
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(defaultValue = "${project.build.directory}", required = true, property = "odc.outputDirectory")
    private File outputDirectory;
    /**
     * This is a reference to the &gt;reporting&lt; sections
     * <code>outputDirectory</code>. This cannot be configured in the
     * dependency-check mojo directly. This generally maps to "target/site".
     */
    @Parameter(property = "project.reporting.outputDirectory", readonly = true)
    private File reportOutputDirectory;
    /**
     * Specifies if the build should be failed if a CVSS score above a specified
     * level is identified. The default is 11 which means since the CVSS scores
     * are 0-10, by default the build will never fail.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "failBuildOnCVSS", defaultValue = "11", required = true)
    private float failBuildOnCVSS = 11f;
    /**
     * Specifies the CVSS score that is considered a "test" failure when
     * generating a jUnit style report. The default value is 0 - all
     * vulnerabilities are considered a failure.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "junitFailOnCVSS", defaultValue = "0", required = true)
    private float junitFailOnCVSS = 0;
    /**
     * Fail the build if any dependency has a vulnerability listed.
     *
     * @deprecated use {@link BaseDependencyCheckMojo#failBuildOnCVSS} with a
     * value of 0 instead
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "failBuildOnAnyVulnerability", defaultValue = "false", required = true)
    @Deprecated
    private boolean failBuildOnAnyVulnerability = false;
    /**
     * Sets whether auto-updating of the NVD CVE data is enabled. It is not
     * recommended that this be turned to false. Default is true.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "autoUpdate")
    private Boolean autoUpdate;
    /**
     * Sets whether Experimental analyzers are enabled. Default is false.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "enableExperimental")
    private Boolean enableExperimental;
    /**
     * Sets whether retired analyzers are enabled. Default is false.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "enableRetired")
    private Boolean enableRetired;
    /**
     * Sets whether the Golang Dependency analyzer is enabled. Default is true.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "golangDepEnabled")
    private Boolean golangDepEnabled;
    /**
     * Sets whether Golang Module Analyzer is enabled; this requires `go` to be
     * installed. Default is true.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "golangModEnabled")
    private Boolean golangModEnabled;
    /**
     * Sets the path to `go`.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pathToGo")
    private String pathToGo;

    /**
     * Sets the path to `yarn`.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pathToYarn")
    private String pathToYarn;
    /**
     * Sets the path to `pnpm`.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pathToPnpm")
    private String pathToPnpm;
    /**
     * Use pom dependency information for snapshot dependencies that are part of
     * the Maven reactor while aggregate scanning a multi-module project.
     */
    @Parameter(property = "dependency-check.virtualSnapshotsFromReactor", defaultValue = "true")
    private Boolean virtualSnapshotsFromReactor;
    /**
     * The report format to be generated (HTML, XML, CSV, JSON, JUNIT, SARIF,
     * JENKINS, GITLAB, ALL). Multiple formats can be selected using a comma
     * delineated list.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "format", defaultValue = "HTML", required = true)
    private String format = "HTML";

    /**
     * Whether or not the XML and JSON report formats should be pretty printed.
     * The default is false.
     */
    @Parameter(property = "prettyPrint")
    private Boolean prettyPrint;
    /**
     * The report format to be generated (HTML, XML, CSV, JSON, JUNIT, SARIF,
     * JENKINS, GITLAB, ALL). Multiple formats can be selected using a comma
     * delineated list.
     */
    @Parameter(property = "formats", required = true)
    private String[] formats;
    /**
     * The Maven settings.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "mavenSettings", defaultValue = "${settings}")
    private org.apache.maven.settings.Settings mavenSettings;

    /**
     * The maven settings proxy id.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "mavenSettingsProxyId")
    private String mavenSettingsProxyId;

    /**
     * The Connection Timeout.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "connectionTimeout")
    private String connectionTimeout;
    /**
     * The Read Timeout.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "readTimeout")
    private String readTimeout;
    /**
     * Sets whether dependency-check should check if there is a new version
     * available.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "versionCheckEnabled", defaultValue = "true")
    private boolean versionCheckEnabled;
    /**
     * The paths to the suppression files. The parameter value can be a local
     * file path, a URL to a suppression file, or even a reference to a file on
     * the class path (see
     * https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799)
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "suppressionFiles")
    private String[] suppressionFiles;
    /**
     * The paths to the suppression file. The parameter value can be a local
     * file path, a URL to a suppression file, or even a reference to a file on
     * the class path (see
     * https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799)
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "suppressionFile")
    private String suppressionFile;
    /**
     * The username used when connecting to the suppressionFiles.
     */
    @Parameter(property = "suppressionFileUser")
    private String suppressionFileUser;
    /**
     * The password used when connecting to the suppressionFiles. The `suppressionFileServerId` should be used instead otherwise maven debug logging could expose the password.
     */
    @Parameter(property = "suppressionFilePassword")
    private String suppressionFilePassword;
    /**
     * The server id in the settings.xml; used to retrieve encrypted passwords
     * from the settings.xml for suppressionFile(s).
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "suppressionFileServerId")
    private String suppressionFileServerId;
    /**
     * The path to the hints file.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "hintsFile")
    private String hintsFile;

    /**
     * Flag indicating whether or not to show a summary in the output.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "showSummary", defaultValue = "true")
    private boolean showSummary = true;

    /**
     * Whether or not the Jar Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "jarAnalyzerEnabled")
    private Boolean jarAnalyzerEnabled;

    /**
     * Sets whether the Dart analyzer is enabled. Default is true.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "dartAnalyzerEnabled")
    private Boolean dartAnalyzerEnabled;

    /**
     * Whether or not the Archive Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "archiveAnalyzerEnabled")
    private Boolean archiveAnalyzerEnabled;
    /**
     * Whether or not the Known Exploited Vulnerability Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "knownExploitedEnabled")
    private Boolean knownExploitedEnabled;
    /**
     * The URL to the CISA Known Exploited Vulnerabilities JSON datafeed.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "knownExploitedUrl")
    private String knownExploitedUrl;
    /**
     * Sets whether the Python Distribution Analyzer will be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pyDistributionAnalyzerEnabled")
    private Boolean pyDistributionAnalyzerEnabled;
    /**
     * Sets whether the Python Package Analyzer will be used.
     */
    @Parameter(property = "pyPackageAnalyzerEnabled")
    private Boolean pyPackageAnalyzerEnabled;
    /**
     * Sets whether the Ruby Gemspec Analyzer will be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "rubygemsAnalyzerEnabled")
    private Boolean rubygemsAnalyzerEnabled;
    /**
     * Sets whether or not the openssl Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "opensslAnalyzerEnabled")
    private Boolean opensslAnalyzerEnabled;
    /**
     * Sets whether or not the CMake Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "cmakeAnalyzerEnabled")
    private Boolean cmakeAnalyzerEnabled;
    /**
     * Sets whether or not the autoconf Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "autoconfAnalyzerEnabled")
    private Boolean autoconfAnalyzerEnabled;
    /**
     * Sets whether or not the Maven install Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "mavenInstallAnalyzerEnabled")
    private Boolean mavenInstallAnalyzerEnabled;
    /**
     * Sets whether or not the pip Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pipAnalyzerEnabled")
    private Boolean pipAnalyzerEnabled;
    /**
     * Sets whether or not the pipfile Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pipfileAnalyzerEnabled")
    private Boolean pipfileAnalyzerEnabled;
    /**
     * Sets whether or not the poetry Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "poetryAnalyzerEnabled")
    private Boolean poetryAnalyzerEnabled;
    /**
     * Sets whether or not the PHP Composer Lock File Analyzer should be used.
     */
    @Parameter(property = "composerAnalyzerEnabled")
    private Boolean composerAnalyzerEnabled;
    /**
     * Whether or not the Perl CPAN File Analyzer is enabled.
     */
    @Parameter(property = "cpanfileAnalyzerEnabled")
    private Boolean cpanfileAnalyzerEnabled;
    /**
     * Sets whether or not the Node.js Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nodeAnalyzerEnabled")
    private Boolean nodeAnalyzerEnabled;
    /**
     * Sets whether or not the Node Audit Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nodeAuditAnalyzerEnabled")
    private Boolean nodeAuditAnalyzerEnabled;

    /**
     * The Node Audit API URL for the Node Audit Analyzer.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nodeAuditAnalyzerUrl")
    private String nodeAuditAnalyzerUrl;

    /**
     * Sets whether or not the Yarn Audit Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "yarnAuditAnalyzerEnabled")
    private Boolean yarnAuditAnalyzerEnabled;

    /**
     * Sets whether or not the Pnpm Audit Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pnpmAuditAnalyzerEnabled")
    private Boolean pnpmAuditAnalyzerEnabled;

    /**
     * Sets whether or not the Node Audit Analyzer should use a local cache.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nodeAuditAnalyzerUseCache")
    private Boolean nodeAuditAnalyzerUseCache;
    /**
     * Sets whether or not the Node Audit Analyzer should skip devDependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nodeAuditSkipDevDependencies")
    private Boolean nodeAuditSkipDevDependencies;
    /**
     * Sets whether or not the Node.js Analyzer should skip devDependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nodePackageSkipDevDependencies")
    private Boolean nodePackageSkipDevDependencies;
    /**
     * Sets whether or not the Retirejs Analyzer should be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "retireJsAnalyzerEnabled")
    private Boolean retireJsAnalyzerEnabled;
    /**
     * The Retire JS repository URL.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "retireJsUrl")
    private String retireJsUrl;
    /**
     * The username to use when connecting to the CVE-URL.
     */
    @Parameter(property = "retireJsUser")
    private String retireJsUser;
    /**
     * The password to authenticate to the CVE-URL. The `retireJsUrlServerId` should be used instead otherwise maven debug logging could expose the password.
     */
    @Parameter(property = "retireJsPassword")
    private String retireJsPassword;
    /**
     * The server id in the settings.xml; used to retrieve encrypted passwords
     * from the settings.xml for cve-URLs.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "retireJsUrlServerId")
    private String retireJsUrlServerId;
    /**
     * Whether the Retire JS repository will be updated regardless of the
     * `autoupdate` settings.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "retireJsForceUpdate")
    private Boolean retireJsForceUpdate;
    /**
     * Whether or not the .NET Assembly Analyzer is enabled.
     */
    @Parameter(property = "assemblyAnalyzerEnabled")
    private Boolean assemblyAnalyzerEnabled;
    /**
     * Whether or not the MS Build Analyzer is enabled.
     */
    @Parameter(property = "msbuildAnalyzerEnabled")
    private Boolean msbuildAnalyzerEnabled;
    /**
     * Whether or not the .NET Nuspec Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nuspecAnalyzerEnabled")
    private Boolean nuspecAnalyzerEnabled;

    /**
     * Whether or not the .NET packages.config Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nugetconfAnalyzerEnabled")
    private Boolean nugetconfAnalyzerEnabled;

    /**
     * Whether or not the Libman Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "libmanAnalyzerEnabled")
    private Boolean libmanAnalyzerEnabled;

    /**
     * Whether or not the Central Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "centralAnalyzerEnabled")
    private Boolean centralAnalyzerEnabled;

    /**
     * Whether or not the Central Analyzer should use a local cache.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "centralAnalyzerUseCache")
    private Boolean centralAnalyzerUseCache;

    /**
     * Whether or not the Artifactory Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerEnabled")
    private Boolean artifactoryAnalyzerEnabled;
    /**
     * The serverId inside the settings.xml containing the username and token to
     * access artifactory
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerServerId")
    private String artifactoryAnalyzerServerId;
    /**
     * The username (only used with API token) to connect to Artifactory
     * instance
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerUsername")
    private String artifactoryAnalyzerUsername;
    /**
     * The API token to connect to Artifactory instance
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerApiToken")
    private String artifactoryAnalyzerApiToken;
    /**
     * The bearer token to connect to Artifactory instance
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerBearerToken")
    private String artifactoryAnalyzerBearerToken;
    /**
     * The Artifactory URL for the Artifactory analyzer.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerUrl")
    private String artifactoryAnalyzerUrl;
    /**
     * Whether Artifactory should be accessed through a proxy or not
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerUseProxy")
    private Boolean artifactoryAnalyzerUseProxy;
    /**
     * Whether the Artifactory analyzer should be run in parallel or not.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "artifactoryAnalyzerParallelAnalysis", defaultValue = "true")
    private Boolean artifactoryAnalyzerParallelAnalysis;
    /**
     * Whether or not the Nexus Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nexusAnalyzerEnabled")
    private Boolean nexusAnalyzerEnabled;

    /**
     * Whether or not the Sonatype OSS Index analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "ossindexAnalyzerEnabled")
    private Boolean ossindexAnalyzerEnabled;
    /**
     * Whether or not the Sonatype OSS Index analyzer should cache results.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "ossindexAnalyzerUseCache")
    private Boolean ossindexAnalyzerUseCache;
    /**
     * URL of the Sonatype OSS Index service.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "ossindexAnalyzerUrl")
    private String ossindexAnalyzerUrl;

    /**
     * The id of a server defined in the settings.xml that configures the
     * credentials (username and password) for a OSS Index service.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "ossIndexServerId")
    private String ossIndexServerId;

    /**
     * Whether we should only warn about Sonatype OSS Index remote errors
     * instead of failing the goal completely.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "ossIndexWarnOnlyOnRemoteErrors")
    private Boolean ossIndexWarnOnlyOnRemoteErrors;

    /**
     * Whether or not the Elixir Mix Audit Analyzer is enabled.
     */
    @Parameter(property = "mixAuditAnalyzerEnabled")
    private Boolean mixAuditAnalyzerEnabled;

    /**
     * Sets the path for the mix_audit binary.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "mixAuditPath")
    private String mixAuditPath;

    /**
     * Whether or not the Ruby Bundle Audit Analyzer is enabled.
     */
    @Parameter(property = "bundleAuditAnalyzerEnabled")
    private Boolean bundleAuditAnalyzerEnabled;

    /**
     * Sets the path for the bundle-audit binary.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "bundleAuditPath")
    private String bundleAuditPath;

    /**
     * Sets the path for the working directory that the bundle-audit binary
     * should be executed from.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "bundleAuditWorkingDirectory")
    private String bundleAuditWorkingDirectory;

    /**
     * Whether or not the CocoaPods Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "cocoapodsAnalyzerEnabled")
    private Boolean cocoapodsAnalyzerEnabled;

    /**
     * Whether or not the Carthage Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "carthageAnalyzerEnabled")
    private Boolean carthageAnalyzerEnabled;

    /**
     * Whether or not the Swift package Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "swiftPackageManagerAnalyzerEnabled")
    private Boolean swiftPackageManagerAnalyzerEnabled;
    /**
     * Whether or not the Swift package resolved Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "swiftPackageResolvedAnalyzerEnabled")
    private Boolean swiftPackageResolvedAnalyzerEnabled;
    /**
     * The URL of a Nexus server's REST API end point
     * (http://domain/nexus/service/local).
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nexusUrl")
    private String nexusUrl;
    /**
     * The id of a server defined in the settings.xml that configures the
     * credentials (username and password) for a Nexus server's REST API end
     * point. When not specified the communication with the Nexus server's REST
     * API will be unauthenticated.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nexusServerId")
    private String nexusServerId;
    /**
     * Whether or not the configured proxy is used to connect to Nexus.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nexusUsesProxy")
    private Boolean nexusUsesProxy;
    /**
     * The database connection string.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "connectionString")
    private String connectionString;

    /**
     * The database driver name. An example would be org.h2.Driver.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "databaseDriverName")
    private String databaseDriverName;
    /**
     * The path to the database driver if it is not on the class path.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "databaseDriverPath")
    private String databaseDriverPath;
    /**
     * A reference to the settings.xml settings.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(defaultValue = "${settings}", readonly = true, required = true)
    private org.apache.maven.settings.Settings settingsXml;
    /**
     * The security dispatcher that can decrypt passwords in the settings.xml.
     */
    @Component(role = SecDispatcher.class, hint = "default")
    private SecDispatcher securityDispatcher;
    /**
     * The database user name.
     */
    @Parameter(property = "databaseUser")
    private String databaseUser;
    /**
     * The password to use when connecting to the database. The `serverId` should be used instead otherwise maven debug logging could expose the password.
     */
    @Parameter(property = "databasePassword")
    private String databasePassword;
    /**
     * A comma-separated list of file extensions to add to analysis next to jar,
     * zip, ....
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "zipExtensions")
    private String zipExtensions;
    /**
     * Skip Dependency Check altogether.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "dependency-check.skip", defaultValue = "false")
    private boolean skip = false;
    /**
     * Skip Analysis for Test Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipTestScope", defaultValue = "true")
    private boolean skipTestScope = true;
    /**
     * Skip Analysis for Runtime Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipRuntimeScope", defaultValue = "false")
    private boolean skipRuntimeScope = false;
    /**
     * Skip Analysis for Provided Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipProvidedScope", defaultValue = "false")
    private boolean skipProvidedScope = false;

    /**
     * Skip Analysis for System Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipSystemScope", defaultValue = "false")
    private boolean skipSystemScope = false;

    /**
     * Skip Analysis for dependencyManagement section.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipDependencyManagement", defaultValue = "true")
    private boolean skipDependencyManagement = true;

    /**
     * Skip analysis for dependencies which type matches this regular
     * expression. This filters on the `type` of dependency as defined in the
     * dependency section: jar, pom, test-jar, etc.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipArtifactType")
    private String skipArtifactType;

    /**
     * The data directory, hold DC SQL DB.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "dataDirectory")
    private String dataDirectory;

    /**
     * The name of the DC DB.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "dbFilename")
    private String dbFilename;
    /**
     * The server id in the settings.xml; used to retrieve encrypted passwords
     * from the settings.xml. This is used for the database username and
     * password.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "serverId")
    private String serverId;
    /**
     * The NVD API Key. The parameters {@link #nvdApiKeyEnvironmentVariable} or {@link #nvdApiServerId} should be used instead otherwise 
     * Maven debug logging could expose the API Key (see <a href="https://github.com/advisories/GHSA-qqhq-8r2c-c3f5">GHSA-qqhq-8r2c-c3f5</a>).
     * This takes precedence over {@link #nvdApiServerId} and {@link #nvdApiKeyEnvironmentVariable}.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nvdApiKey")
    private String nvdApiKey;
    /**
     * The maximum number of retry requests for a single call to the NVD API.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nvdMaxRetryCount")
    private Integer nvdMaxRetryCount;
    /**
     * The server id in the settings.xml; used to retrieve encrypted API Key
     * from the settings.xml for the NVD API Key. Note that the password is used
     * as the API Key.
     * Is potentially overwritten by {@link #nvdApiKeyEnvironmentVariable} or {@link #nvdApiKey}.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nvdApiServerId")
    private String nvdApiServerId;
    /**
     * The environment variable from which to retrieve the API key for the NVD API.
     * Takes precedence over {@link #nvdApiServerId} but is potentially overwritten by {@link #nvdApiKey}.
     * This is the recommended option to pass the API key in CI builds.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nvdApiKeyEnvironmentVariable")
    private String nvdApiKeyEnvironmentVariable;
    /**
     * The number of hours to wait before checking for new updates from the NVD.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nvdValidForHours")
    private Integer nvdValidForHours;
    /**
     * The NVD API Endpoint; setting this is uncommon.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nvdApiEndpoint")
    private String nvdApiEndpoint;
    /**
     * The NVD API Data Feed URL.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nvdDatafeedUrl")
    private String nvdDatafeedUrl;

    /**
     * The server id in the settings.xml; used to retrieve encrypted passwords
     * from the settings.xml for the NVD Data Feed.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nvdDatafeedServerId")
    private String nvdDatafeedServerId;
    /**
     * The username for basic auth to the NVD Data Feed.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nvdUser")
    private String nvdUser;
    /**
     * The password for basic auth to the NVD Data Feed.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nvdPassword")
    private String nvdPassword;
    /**
     * The time in milliseconds to wait between downloading NVD API data.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nvdApiDelay")
    private Integer nvdApiDelay;

    /**
     * The number records for a single page from NVD API (must be <=2000).
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nvdApiResultsPerPage")
    private Integer nvdApiResultsPerPage;

    /**
     * The path to dotnet core.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "pathToCore")
    private String pathToCore;
    /**
     * The hosted suppressions file URL.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "hostedSuppressionsUrl")
    private String hostedSuppressionsUrl;
    /**
     * Whether the hosted suppressions file will be updated regardless of the
     * `autoupdate` settings.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "hostedSuppressionsForceUpdate")
    private Boolean hostedSuppressionsForceUpdate;
    /**
     * Whether the hosted suppressions file will be used.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "hostedSuppressionsEnabled")
    private Boolean hostedSuppressionsEnabled;
    /**
     * Skip excessive hosted suppression file update checks for a designated
     * duration in hours (defaults to 2 hours).
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "hostedSuppressionsValidForHours")
    private Integer hostedSuppressionsValidForHours;

    /**
     * The RetireJS Analyzer configuration:
     * <pre>
     *   filters: an array of filter patterns that are used to exclude JS files that contain a match
     *   filterNonVulnerable: a boolean that when true will remove non-vulnerable JS from the report
     *
     * Example:
     *   &lt;retirejs&gt;
     *     &lt;filters&gt;
     *       &lt;filter&gt;copyright 2018\(c\) Jeremy Long&lt;/filter&gt;
     *     &lt;/filters&gt;
     *     &lt;filterNonVulnerable&gt;true&lt;/filterNonVulnerable&gt;
     *   &lt;/retirejs&gt;
     * </pre>
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "retirejs")
    private Retirejs retirejs;

    /**
     * The list of artifacts (and their transitive dependencies) to exclude from
     * the check.
     */
    @Parameter(property = "odc.excludes")
    private List<String> excludes;

    /**
     * The artifact scope filter.
     */
    private Filter<String> artifactScopeExcluded;

    /**
     * Filter for artifact type.
     */
    private Filter<String> artifactTypeExcluded;

    /**
     * An collection of <code>fileSet</code>s that specify additional files
     * and/or directories (from the basedir) to analyze as part of the scan. If
     * not specified, defaults to Maven conventions of: src/main/resources,
     * src/main/filters, and src/main/webapp. Note, this cannot be set via the
     * command line - use `scanDirectory` instead.
     */
    @Parameter
    private List<FileSet> scanSet;
    /**
     * A list of directories to scan. Note, this should only be used via the
     * command line - if configuring the directories to scan consider using the
     * `scanSet` instead.
     */
    @Parameter(property = "scanDirectory")
    private List<String> scanDirectory;

    /**
     * Whether the project's plugins should also be scanned.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "odc.plugins.scan", defaultValue = "false", required = false)
    private boolean scanPlugins = false;
    /**
     * Whether the project's dependencies should also be scanned.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "odc.dependencies.scan", defaultValue = "true", required = false)
    private boolean scanDependencies = true;
    /**
     * The proxy configuration.
     */
    @Parameter
    private ProxyConfig proxy;

    // </editor-fold>
    //<editor-fold defaultstate="collapsed" desc="Base Maven implementation">
    /**
     * Determines if the groupId, artifactId, and version of the Maven
     * dependency and artifact match.
     *
     * @param d the Maven dependency
     * @param a the Maven artifact
     * @return true if the groupId, artifactId, and version match
     */
    private static boolean artifactsMatch(org.apache.maven.model.Dependency d, Artifact a) {
        return isEqualOrNull(a.getArtifactId(), d.getArtifactId())
                && isEqualOrNull(a.getGroupId(), d.getGroupId())
                && isEqualOrNull(a.getVersion(), d.getVersion());
    }

    /**
     * Compares two strings for equality; if both strings are null they are
     * considered equal.
     *
     * @param left the first string to compare
     * @param right the second string to compare
     * @return true if the strings are equal or if they are both null; otherwise
     * false.
     */
    private static boolean isEqualOrNull(String left, String right) {
        return (left != null && left.equals(right)) || (left == null && right == null);
    }

    /**
     * Executes dependency-check.
     *
     * @throws MojoExecutionException thrown if there is an exception executing
     * the mojo
     * @throws MojoFailureException thrown if dependency-check failed the build
     */
    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        generatingSite = false;
        final boolean shouldSkip = Boolean.parseBoolean(System.getProperty("dependency-check.skip", Boolean.toString(skip)));
        if (shouldSkip) {
            getLog().info("Skipping " + getName(Locale.US));
        } else {
            project.setContextValue("dependency-check-output-dir", this.outputDirectory);
            runCheck();
        }
    }

    /**
     * Generates the Dependency-Check Site Report.
     *
     * @param sink the sink to write the report to
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     * @deprecated use
     * {@link #generate(org.apache.maven.doxia.sink.Sink, java.util.Locale)}
     * instead.
     */
    @Deprecated
    public final void generate(@SuppressWarnings("deprecation") org.codehaus.doxia.sink.Sink sink, Locale locale) throws MavenReportException {
        generate((Sink) sink, locale);
    }

    /**
     * Returns true if the Maven site is being generated.
     *
     * @return true if the Maven site is being generated
     */
    protected boolean isGeneratingSite() {
        return generatingSite;
    }

    /**
     * Returns the connection string.
     *
     * @return the connection string
     */
    protected String getConnectionString() {
        return connectionString;
    }

    /**
     * Returns if the mojo should fail the build if an exception occurs.
     *
     * @return whether or not the mojo should fail the build
     */
    protected boolean isFailOnError() {
        return failOnError;
    }

    /**
     * Generates the Dependency-Check Site Report.
     *
     * @param sink the sink to write the report to
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     */
    public void generate(Sink sink, Locale locale) throws MavenReportException {
        final boolean shouldSkip = Boolean.parseBoolean(System.getProperty("dependency-check.skip", Boolean.toString(skip)));
        if (shouldSkip) {
            getLog().info("Skipping report generation " + getName(Locale.US));
            return;
        }

        generatingSite = true;
        project.setContextValue("dependency-check-output-dir", getReportOutputDirectory());
        try {
            runCheck();
        } catch (MojoExecutionException ex) {
            throw new MavenReportException(ex.getMessage(), ex);
        } catch (MojoFailureException ex) {
            getLog().warn("Vulnerabilities were identifies that exceed the CVSS threshold for failing the build");
        }
    }

    /**
     * Returns the correct output directory depending on if a site is being
     * executed or not.
     *
     * @return the directory to write the report(s)
     * @throws MojoExecutionException thrown if there is an error loading the
     * file path
     */
    protected File getCorrectOutputDirectory() throws MojoExecutionException {
        return getCorrectOutputDirectory(this.project);
    }

    /**
     * Returns the correct output directory depending on if a site is being
     * executed or not.
     *
     * @param current the Maven project to get the output directory from
     * @return the directory to write the report(s)
     */
    protected File getCorrectOutputDirectory(MavenProject current) {
        final Object obj = current.getContextValue("dependency-check-output-dir");
        if (obj != null && obj instanceof File) {
            return (File) obj;
        }
        //else we guess
        File target = new File(current.getBuild().getDirectory());
        if (target.getParentFile() != null && "target".equals(target.getParentFile().getName())) {
            target = target.getParentFile();
        }
        return target;
    }

    /**
     * Scans the project's artifacts and adds them to the engine's dependency
     * list.
     *
     * @param project the project to scan the dependencies of
     * @param engine the engine to use to scan the dependencies
     * @return a collection of exceptions that may have occurred while resolving
     * and scanning the dependencies
     */
    protected ExceptionCollection scanArtifacts(MavenProject project, Engine engine) {
        return scanArtifacts(project, engine, false);
    }

    /**
     * Scans the project's artifacts and adds them to the engine's dependency
     * list.
     *
     * @param project the project to scan the dependencies of
     * @param engine the engine to use to scan the dependencies
     * @param aggregate whether the scan is part of an aggregate build
     * @return a collection of exceptions that may have occurred while resolving
     * and scanning the dependencies
     */
    protected ExceptionCollection scanArtifacts(MavenProject project, Engine engine, boolean aggregate) {
        try {
            final List<String> filterItems = Collections.singletonList(String.format("%s:%s", project.getGroupId(), project.getArtifactId()));
            final ProjectBuildingRequest buildingRequest = newResolveArtifactProjectBuildingRequest(project, project.getRemoteArtifactRepositories());
            //For some reason the filter does not filter out the project being analyzed
            //if we pass in the filter below instead of null to the dependencyGraphBuilder
            final DependencyNode dn = dependencyGraphBuilder.buildDependencyGraph(buildingRequest, null);

            final CollectingRootDependencyGraphVisitor collectorVisitor = new CollectingRootDependencyGraphVisitor();

            // exclude artifact by pattern and its dependencies
            final DependencyNodeVisitor transitiveFilterVisitor = new FilteringDependencyTransitiveNodeVisitor(collectorVisitor,
                    new ArtifactDependencyNodeFilter(new PatternExcludesArtifactFilter(getExcludes())));
            // exclude exact artifact but not its dependencies, this filter must be appied on the root for first otherwise
            // in case the exclude has the same groupId of the current bundle its direct dependencies are not visited
            final DependencyNodeVisitor artifactFilter = new FilteringDependencyNodeVisitor(transitiveFilterVisitor,
                    new ArtifactDependencyNodeFilter(new ExcludesArtifactFilter(filterItems)));
            dn.accept(artifactFilter);

            //collect dependencies with the filter - see comment above.
            final Map<DependencyNode, List<DependencyNode>> nodes = collectorVisitor.getNodes();

            return collectDependencies(engine, project, nodes, buildingRequest, aggregate);
        } catch (DependencyGraphBuilderException ex) {
            final String msg = String.format("Unable to build dependency graph on project %s", project.getName());
            getLog().debug(msg, ex);
            return new ExceptionCollection(ex);
        }
    }

    /**
     * Scans the project's artifacts for plugin-dependencies and adds them to
     * the engine's dependency list.
     *
     * @param project the project to scan the plugin-dependencies of
     * @param engine the engine to use to scan the plugin-dependencies
     * @param exCollection the collection of exceptions that have previously
     * occurred
     * @return a collection of exceptions that may have occurred while resolving
     * and scanning the plugins and their dependencies
     */
    protected ExceptionCollection scanPlugins(MavenProject project, Engine engine, ExceptionCollection exCollection) {
        ExceptionCollection exCol = exCollection;
        final Set<Artifact> plugins = new HashSet<>();
        final Set<Artifact> buildPlugins = getProject().getPluginArtifacts();
        final Set<Artifact> reportPlugins = getProject().getReportArtifacts();
        final Set<Artifact> extensions = getProject().getExtensionArtifacts();

        plugins.addAll(buildPlugins);
        plugins.addAll(reportPlugins);
        plugins.addAll(extensions);

        final ProjectBuildingRequest buildingRequest = newResolveArtifactProjectBuildingRequest(project, project.getPluginArtifactRepositories());
        for (Artifact plugin : plugins) {
            try {
                final Artifact resolved = artifactResolver.resolveArtifact(buildingRequest, plugin).getArtifact();

                exCol = addPluginToDependencies(project, engine, resolved, "pom.xml (plugins)", exCol);

                final DefaultDependableCoordinate pluginCoordinate = new DefaultDependableCoordinate();
                pluginCoordinate.setGroupId(resolved.getGroupId());
                pluginCoordinate.setArtifactId(resolved.getArtifactId());
                pluginCoordinate.setVersion(resolved.getVersion());

                final String parent = buildReference(resolved.getGroupId(), resolved.getArtifactId(), resolved.getVersion());
                for (Artifact artifact : resolveArtifactDependencies(pluginCoordinate, project)) {
                    exCol = addPluginToDependencies(project, engine, artifact, parent, exCol);
                }
            } catch (ArtifactResolverException ex) {
                throw new RuntimeException(ex);
            } catch (IllegalArgumentException ex) {
                throw new RuntimeException(ex);
            } catch (DependencyResolverException ex) {
                throw new RuntimeException(ex);
            }
        }

        return null;

    }

    private ExceptionCollection addPluginToDependencies(MavenProject project, Engine engine, Artifact artifact, String parent, ExceptionCollection exCollection) {
        ExceptionCollection exCol = exCollection;
        final String groupId = artifact.getGroupId();
        final String artifactId = artifact.getArtifactId();
        final String version = artifact.getVersion();
        final File artifactFile = artifact.getFile();
        if (artifactFile.isFile()) {
            final List<ArtifactVersion> availableVersions = artifact.getAvailableVersions();

            final List<Dependency> deps = engine.scan(artifactFile.getAbsoluteFile(),
                    project.getName() + " (plugins)");
            if (deps != null) {
                Dependency d = null;
                if (deps.size() == 1) {
                    d = deps.get(0);
                } else {
                    for (Dependency possible : deps) {
                        if (artifactFile.getAbsoluteFile().equals(possible.getActualFile())) {
                            d = possible;
                            break;
                        }
                    }
                    for (Dependency dep : deps) {
                        if (d != null && d != dep) {
                            final String includedBy = buildReference(groupId, artifactId, version);
                            dep.addIncludedBy(includedBy, "plugins");
                        }
                    }
                }
                if (d != null) {
                    final MavenArtifact ma = new MavenArtifact(groupId, artifactId, version);
                    d.addAsEvidence("pom", ma, Confidence.HIGHEST);
                    if (parent != null) {
                        d.addIncludedBy(parent, "plugins");
                    } else {
                        final String includedby = buildReference(
                                project.getGroupId(),
                                project.getArtifactId(),
                                project.getVersion());
                        d.addIncludedBy(includedby, "plugins");
                    }
                    if (availableVersions != null) {
                        for (ArtifactVersion av : availableVersions) {
                            d.addAvailableVersion(av.toString());
                        }
                    }
                }
            }
        } else {
            if (exCol == null) {
                exCol = new ExceptionCollection();
            }
            exCol.addException(new DependencyNotFoundException("Unable to resolve plugin: "
                    + groupId + ":" + artifactId + ":" + version));
        }

        return exCol;
    }

    private String buildReference(final String groupId, final String artifactId, final String version) {
        String includedBy;
        try {
            final PackageURL purl = new PackageURL("maven", groupId, artifactId, version, null, null);
            includedBy = purl.toString();
        } catch (MalformedPackageURLException ex) {
            getLog().warn("Unable to generate build reference for " + groupId
                    + ":" + artifactId + ":" + version, ex);
            includedBy = groupId + ":" + artifactId + ":" + version;
        }
        return includedBy;
    }

    protected Set<Artifact> resolveArtifactDependencies(final DependableCoordinate artifact, MavenProject project)
            throws DependencyResolverException {
        final ProjectBuildingRequest buildingRequest = newResolveArtifactProjectBuildingRequest(project, project.getRemoteArtifactRepositories());

        final Iterable<ArtifactResult> artifactResults = dependencyResolver.resolveDependencies(buildingRequest, artifact, null);

        final Set<Artifact> artifacts = new HashSet<>();

        for (ArtifactResult artifactResult : artifactResults) {
            artifacts.add(artifactResult.getArtifact());
        }

        return artifacts;

    }

    /**
     * Converts the dependency to a dependency node object.
     *
     * @param nodes the list of dependency nodes
     * @param buildingRequest the Maven project building request
     * @param parent the parent node
     * @param dependency the dependency to convert
     * @return the resulting dependency node
     * @throws ArtifactResolverException thrown if the artifact could not be
     * retrieved
     */
    private DependencyNode toDependencyNode(List<DependencyNode> nodes, ProjectBuildingRequest buildingRequest,
            DependencyNode parent, org.apache.maven.model.Dependency dependency) throws ArtifactResolverException {

        final DefaultArtifactCoordinate coordinate = new DefaultArtifactCoordinate();

        coordinate.setGroupId(dependency.getGroupId());
        coordinate.setArtifactId(dependency.getArtifactId());
        String version = null;
        final VersionRange vr;
        try {
            vr = VersionRange.createFromVersionSpec(dependency.getVersion());
        } catch (InvalidVersionSpecificationException ex) {
            throw new ArtifactResolverException("Invalid version specification: "
                    + dependency.getGroupId() + ":"
                    + dependency.getArtifactId() + ":"
                    + dependency.getVersion(), ex);
        }
        if (vr.hasRestrictions()) {
            version = findVersion(nodes, dependency.getGroupId(), dependency.getArtifactId());
            if (version == null) {
                //TODO - this still may fail if the restriction is not a valid version number (i.e. only 2.9 instead of 2.9.1)
                //need to get available versions and filter on the restrictions.
                if (vr.getRecommendedVersion() != null) {
                    version = vr.getRecommendedVersion().toString();
                } else if (vr.hasRestrictions()) {
                    for (Restriction restriction : vr.getRestrictions()) {
                        if (restriction.getLowerBound() != null) {
                            version = restriction.getLowerBound().toString();
                        }
                        if (restriction.getUpperBound() != null) {
                            version = restriction.getUpperBound().toString();
                        }
                    }
                } else {
                    version = vr.toString();
                }
            }
        }
        if (version == null) {
            version = dependency.getVersion();
        }
        coordinate.setVersion(version);

        final ArtifactType type = session.getRepositorySession().getArtifactTypeRegistry().get(dependency.getType());
        coordinate.setExtension(type.getExtension());
        coordinate.setClassifier((null == dependency.getClassifier() || dependency.getClassifier().isEmpty())
                ? type.getClassifier() : dependency.getClassifier());
        final Artifact artifact = artifactResolver.resolveArtifact(buildingRequest, coordinate).getArtifact();
        artifact.setScope(dependency.getScope());
        return new DefaultDependencyNode(parent, artifact, dependency.getVersion(), dependency.getScope(), null);
    }

    /**
     * Returns the version from the list of nodes that match the given groupId
     * and artifactID.
     *
     * @param nodes the nodes to search
     * @param groupId the group id to find
     * @param artifactId the artifact id to find
     * @return the version from the list of nodes that match the given groupId
     * and artifactID; otherwise <code>null</code> is returned
     */
    private String findVersion(List<DependencyNode> nodes, String groupId, String artifactId) {
        final Optional<DependencyNode> f = nodes.stream().filter(p
                -> groupId.equals(p.getArtifact().getGroupId())
                && artifactId.equals(p.getArtifact().getArtifactId())).findFirst();
        if (f.isPresent()) {
            return f.get().getArtifact().getVersion();
        }
        return null;
    }

    /**
     * Collect dependencies from the dependency management section.
     *
     * @param engine reference to the ODC engine
     * @param buildingRequest the Maven project building request
     * @param project the project being analyzed
     * @param nodes the list of dependency nodes
     * @param aggregate whether or not this is an aggregate analysis
     * @return a collection of exceptions if any occurred; otherwise
     * <code>null</code>
     */
    private ExceptionCollection collectDependencyManagementDependencies(Engine engine, ProjectBuildingRequest buildingRequest,
            MavenProject project, List<DependencyNode> nodes, boolean aggregate) {
        if (skipDependencyManagement || project.getDependencyManagement() == null) {
            return null;
        }

        ExceptionCollection exCol = null;
        for (org.apache.maven.model.Dependency dependency : project.getDependencyManagement().getDependencies()) {
            try {
                nodes.add(toDependencyNode(nodes, buildingRequest, null, dependency));
            } catch (ArtifactResolverException ex) {
                getLog().debug(String.format("Aggregate : %s", aggregate));
                boolean addException = true;
                //CSOFF: EmptyBlock
                if (!aggregate) {
                    // do nothing, exception is to be reported
                } else if (addReactorDependency(engine,
                        new DefaultArtifact(dependency.getGroupId(), dependency.getArtifactId(),
                                dependency.getVersion(), dependency.getScope(), dependency.getType(), dependency.getClassifier(),
                                new DefaultArtifactHandler()), project)) {
                    addException = false;
                }
                //CSON: EmptyBlock
                if (addException) {
                    if (exCol == null) {
                        exCol = new ExceptionCollection();
                    }
                    exCol.addException(ex);
                }
            }
        }
        return exCol;
    }

    /**
     * Resolves the projects artifacts using Aether and scans the resulting
     * dependencies.
     *
     * @param engine the core dependency-check engine
     * @param project the project being scanned
     * @param nodeMap the map of dependency nodes, generally obtained via the
     * DependencyGraphBuilder using the CollectingRootDependencyGraphVisitor
     * @param buildingRequest the Maven project building request
     * @param aggregate whether the scan is part of an aggregate build
     * @return a collection of exceptions that may have occurred while resolving
     * and scanning the dependencies
     */
    //CSOFF: OperatorWrap
    private ExceptionCollection collectMavenDependencies(Engine engine, MavenProject project,
            Map<DependencyNode, List<DependencyNode>> nodeMap, ProjectBuildingRequest buildingRequest, boolean aggregate) {

        final List<ArtifactResult> allResolvedDeps = new ArrayList<>();

        //dependency management
        final List<DependencyNode> dmNodes = new ArrayList<>();
        ExceptionCollection exCol = collectDependencyManagementDependencies(engine, buildingRequest, project, dmNodes, aggregate);
        for (DependencyNode dependencyNode : dmNodes) {
            exCol = scanDependencyNode(dependencyNode, null, engine, project, allResolvedDeps, buildingRequest, aggregate, exCol);
        }

        //dependencies
        for (Map.Entry<DependencyNode, List<DependencyNode>> entry : nodeMap.entrySet()) {
            exCol = scanDependencyNode(entry.getKey(), null, engine, project, allResolvedDeps, buildingRequest, aggregate, exCol);
            for (DependencyNode dependencyNode : entry.getValue()) {
                exCol = scanDependencyNode(dependencyNode, entry.getKey(), engine, project, allResolvedDeps, buildingRequest, aggregate, exCol);
            }
        }
        return exCol;
    }
    //CSON: OperatorWrap

    /**
     * Utility method for a work-around to MSHARED-998
     *
     * @param allDeps The List of ArtifactResults for all dependencies
     * @param unresolvedArtifact The ArtifactCoordinate of the artifact we're
     * looking for
     * @param project The project in whose context resolution was attempted
     * @return the resolved artifact matching with {@code unresolvedArtifact}
     * @throws DependencyNotFoundException If {@code unresolvedArtifact} could
     * not be found within {@code allDeps}
     */
    private Artifact findInAllDeps(final List<ArtifactResult> allDeps, final Artifact unresolvedArtifact,
            final MavenProject project)
            throws DependencyNotFoundException {
        Artifact result = null;
        for (final ArtifactResult res : allDeps) {
            if (sameArtifact(res, unresolvedArtifact)) {
                result = res.getArtifact();
                break;
            }
        }
        if (result == null) {
            throw new DependencyNotFoundException(String.format("Expected dependency not found in resolved artifacts for "
                    + "dependency %s of project-artifact %s", unresolvedArtifact, project.getArtifactId()));
        }
        return result;
    }

    /**
     * Utility method for a work-around to MSHARED-998
     *
     * @param res A single ArtifactResult obtained from the DependencyResolver
     * @param unresolvedArtifact The unresolved Artifact from the
     * dependencyGraph that we try to find
     * @return {@code true} when unresolvedArtifact is non-null and matches with
     * the artifact of res
     */
    private boolean sameArtifact(final ArtifactResult res, final Artifact unresolvedArtifact) {
        if (res == null || res.getArtifact() == null || unresolvedArtifact == null) {
            return false;
        }
        boolean result = Objects.equals(res.getArtifact().getGroupId(), unresolvedArtifact.getGroupId());
        result &= Objects.equals(res.getArtifact().getArtifactId(), unresolvedArtifact.getArtifactId());
        // accept any version as matching "LATEST" and any non-snapshot version as matching "RELEASE" meta-version
        if ("RELEASE".equals(unresolvedArtifact.getBaseVersion())) {
            result &= !res.getArtifact().isSnapshot();
        } else if (!"LATEST".equals(unresolvedArtifact.getBaseVersion())) {
            result &= Objects.equals(res.getArtifact().getBaseVersion(), unresolvedArtifact.getBaseVersion());
        }
        result &= Objects.equals(res.getArtifact().getClassifier(), unresolvedArtifact.getClassifier());
        result &= Objects.equals(res.getArtifact().getType(), unresolvedArtifact.getType());
        return result;
    }

    /**
     * @param project the {@link MavenProject}
     * @param dependencyNode the {@link DependencyNode}
     * @return the name to be used when creating a
     * {@link Dependency#getProjectReferences() project reference} in a
     * {@link Dependency}. The behavior of this method returns {@link MavenProject#getName() project.getName()}<code> + ":" +
     * </code>
     * {@link DependencyNode#getArtifact() dependencyNode.getArtifact()}{@link Artifact#getScope() .getScope()}.
     */
    protected String createProjectReferenceName(MavenProject project, DependencyNode dependencyNode) {
        return project.getName() + ":" + dependencyNode.getArtifact().getScope();
    }

    /**
     * Scans the projects dependencies including the default (or defined)
     * FileSets.
     *
     * @param engine the core dependency-check engine
     * @param project the project being scanned
     * @param nodes the list of dependency nodes, generally obtained via the
     * DependencyGraphBuilder
     * @param buildingRequest the Maven project building request
     * @param aggregate whether the scan is part of an aggregate build
     * @return a collection of exceptions that may have occurred while resolving
     * and scanning the dependencies
     */
    private ExceptionCollection collectDependencies(Engine engine, MavenProject project,
            Map<DependencyNode, List<DependencyNode>> nodes, ProjectBuildingRequest buildingRequest, boolean aggregate) {

        ExceptionCollection exCol;
        exCol = collectMavenDependencies(engine, project, nodes, buildingRequest, aggregate);

        final List<FileSet> projectScan;

        if (scanDirectory != null && !scanDirectory.isEmpty()) {
            if (scanSet == null) {
                scanSet = new ArrayList<>();
            }
            scanDirectory.forEach(d -> {
                final FileSet fs = new FileSet();
                fs.setDirectory(d);
                fs.addInclude(INCLUDE_ALL);
                scanSet.add(fs);
            });
        }

        if (scanSet == null || scanSet.isEmpty()) {
            // Define the default FileSets
            final FileSet resourcesSet = new FileSet();
            final FileSet filtersSet = new FileSet();
            final FileSet webappSet = new FileSet();
            final FileSet mixedLangSet = new FileSet();
            try {
                resourcesSet.setDirectory(new File(project.getBasedir(), "src/main/resources").getCanonicalPath());
                resourcesSet.addInclude(INCLUDE_ALL);
                filtersSet.setDirectory(new File(project.getBasedir(), "src/main/filters").getCanonicalPath());
                filtersSet.addInclude(INCLUDE_ALL);
                webappSet.setDirectory(new File(project.getBasedir(), "src/main/webapp").getCanonicalPath());
                webappSet.addInclude(INCLUDE_ALL);
                mixedLangSet.setDirectory(project.getBasedir().getCanonicalPath());
                mixedLangSet.addInclude("package.json");
                mixedLangSet.addInclude("package-lock.json");
                mixedLangSet.addInclude("npm-shrinkwrap.json");
                mixedLangSet.addInclude("Gopkg.lock");
                mixedLangSet.addInclude("go.mod");
                mixedLangSet.addInclude("yarn.lock");
                mixedLangSet.addInclude("pnpm-lock.yaml");
                mixedLangSet.addExclude("/node_modules/");
            } catch (IOException ex) {
                if (exCol == null) {
                    exCol = new ExceptionCollection();
                }
                exCol.addException(ex);
            }
            projectScan = new ArrayList<>();
            projectScan.add(resourcesSet);
            projectScan.add(filtersSet);
            projectScan.add(webappSet);
            projectScan.add(mixedLangSet);

        } else if (aggregate) {
            projectScan = new ArrayList<>();
            for (FileSet copyFrom : scanSet) {
                //deep copy of the FileSet - modifying the directory if it is not absolute.
                final FileSet fsCopy = new FileSet();
                final File f = new File(copyFrom.getDirectory());
                if (f.isAbsolute()) {
                    fsCopy.setDirectory(copyFrom.getDirectory());
                } else {
                    try {
                        fsCopy.setDirectory(new File(project.getBasedir(), copyFrom.getDirectory()).getCanonicalPath());
                    } catch (IOException ex) {
                        if (exCol == null) {
                            exCol = new ExceptionCollection();
                        }
                        exCol.addException(ex);
                        fsCopy.setDirectory(copyFrom.getDirectory());
                    }
                }
                fsCopy.setDirectoryMode(copyFrom.getDirectoryMode());
                fsCopy.setExcludes(copyFrom.getExcludes());
                fsCopy.setFileMode(copyFrom.getFileMode());
                fsCopy.setFollowSymlinks(copyFrom.isFollowSymlinks());
                fsCopy.setIncludes(copyFrom.getIncludes());
                fsCopy.setLineEnding(copyFrom.getLineEnding());
                fsCopy.setMapper(copyFrom.getMapper());
                fsCopy.setModelEncoding(copyFrom.getModelEncoding());
                fsCopy.setOutputDirectory(copyFrom.getOutputDirectory());
                fsCopy.setUseDefaultExcludes(copyFrom.isUseDefaultExcludes());
                projectScan.add(fsCopy);
            }
        } else {
            projectScan = scanSet;
        }

        // Iterate through FileSets and scan included files
        final FileSetManager fileSetManager = new FileSetManager();
        for (FileSet fileSet : projectScan) {
            getLog().debug("Scanning fileSet: " + fileSet.getDirectory());
            final String[] includedFiles = fileSetManager.getIncludedFiles(fileSet);
            for (String include : includedFiles) {
                final File includeFile = new File(fileSet.getDirectory(), include).getAbsoluteFile();
                if (includeFile.exists()) {
                    engine.scan(includeFile, project.getName());
                }
            }
        }
        return exCol;
    }

    /**
     * Checks if the current artifact is actually in the reactor projects that
     * have not yet been built. If true a virtual dependency is created based on
     * the evidence in the project.
     *
     * @param engine a reference to the engine being used to scan
     * @param artifact the artifact being analyzed in the mojo
     * @param depender The project that depends on this virtual dependency
     * @return <code>true</code> if the artifact is in the reactor; otherwise
     * <code>false</code>
     */
    private boolean addReactorDependency(Engine engine, Artifact artifact, final MavenProject depender) {
        return addVirtualDependencyFromReactor(engine, artifact, depender, "Unable to resolve %s as it has not been built yet "
                + "- creating a virtual dependency instead.");
    }

    /**
     * Checks if the current artifact is actually in the reactor projects. If
     * true a virtual dependency is created based on the evidence in the
     * project.
     *
     * @param engine a reference to the engine being used to scan
     * @param artifact the artifact being analyzed in the mojo
     * @param depender The project that depends on this virtual dependency
     * @param infoLogTemplate the template for the infoLog entry written when a
     * virtual dependency is added. Needs a single %s placeholder for the
     * location of the displayName in the message
     * @return <code>true</code> if the artifact is in the reactor; otherwise
     * <code>false</code>
     */
    private boolean addVirtualDependencyFromReactor(Engine engine, Artifact artifact,
            final MavenProject depender, String infoLogTemplate) {

        getLog().debug(String.format("Checking the reactor projects (%d) for %s:%s:%s",
                reactorProjects.size(),
                artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion()));

        for (MavenProject prj : reactorProjects) {

            getLog().debug(String.format("Comparing %s:%s:%s to %s:%s:%s",
                    artifact.getGroupId(), artifact.getArtifactId(), artifact.getBaseVersion(),
                    prj.getGroupId(), prj.getArtifactId(), prj.getVersion()));

            if (prj.getArtifactId().equals(artifact.getArtifactId())
                    && prj.getGroupId().equals(artifact.getGroupId())
                    && prj.getVersion().equals(artifact.getBaseVersion())) {

                final String displayName = String.format("%s:%s:%s",
                        prj.getGroupId(), prj.getArtifactId(), prj.getVersion());
                getLog().info(String.format(infoLogTemplate,
                        displayName));
                final Dependency d = newDependency(prj);
                final String key = String.format("%s:%s:%s", prj.getGroupId(), prj.getArtifactId(), prj.getVersion());
                d.setSha1sum(Checksum.getSHA1Checksum(key));
                d.setSha256sum(Checksum.getSHA256Checksum(key));
                d.setMd5sum(Checksum.getMD5Checksum(key));
                d.setEcosystem(JarAnalyzer.DEPENDENCY_ECOSYSTEM);
                d.setDisplayFileName(displayName);
                d.addProjectReference(depender.getName());
                final String includedby = buildReference(
                        depender.getGroupId(),
                        depender.getArtifactId(),
                        depender.getVersion());
                d.addIncludedBy(includedby);
                d.addEvidence(EvidenceType.PRODUCT, "project", "artifactid", prj.getArtifactId(), Confidence.HIGHEST);
                d.addEvidence(EvidenceType.VENDOR, "project", "artifactid", prj.getArtifactId(), Confidence.LOW);

                d.addEvidence(EvidenceType.VENDOR, "project", "groupid", prj.getGroupId(), Confidence.HIGHEST);
                d.addEvidence(EvidenceType.PRODUCT, "project", "groupid", prj.getGroupId(), Confidence.LOW);
                d.setEcosystem(JarAnalyzer.DEPENDENCY_ECOSYSTEM);
                Identifier id;
                try {
                    id = new PurlIdentifier(StandardTypes.MAVEN, artifact.getGroupId(),
                            artifact.getArtifactId(), artifact.getVersion(), Confidence.HIGHEST);
                } catch (MalformedPackageURLException ex) {
                    getLog().debug("Unable to create PackageURL object:" + key);
                    id = new GenericIdentifier("maven:" + key, Confidence.HIGHEST);
                }
                d.addSoftwareIdentifier(id);
                //TODO unify the setName/version and package path - they are equivelent ideas submitted by two seperate committers
                d.setName(String.format("%s:%s", prj.getGroupId(), prj.getArtifactId()));
                d.setVersion(prj.getVersion());
                d.setPackagePath(displayName);
                if (prj.getDescription() != null) {
                    JarAnalyzer.addDescription(d, prj.getDescription(), "project", "description");
                }
                for (License l : prj.getLicenses()) {
                    final StringBuilder license = new StringBuilder();
                    if (l.getName() != null) {
                        license.append(l.getName());
                    }
                    if (l.getUrl() != null) {
                        license.append(" ").append(l.getUrl());
                    }
                    if (d.getLicense() == null) {
                        d.setLicense(license.toString());
                    } else if (!d.getLicense().contains(license)) {
                        d.setLicense(String.format("%s%n%s", d.getLicense(), license));
                    }
                }
                engine.addDependency(d);
                return true;
            }
        }
        return false;
    }

    Dependency newDependency(MavenProject prj) {
        final File pom = new File(prj.getBasedir(), "pom.xml");

        if (pom.isFile()) {
            getLog().debug("Adding virtual dependency from pom.xml");
            return new Dependency(pom, true);
        } else if (prj.getFile().isFile()) {
            getLog().debug("Adding virtual dependency from file");
            return new Dependency(prj.getFile(), true);
        } else {
            return new Dependency(true);
        }
    }

    /**
     * Checks if the current artifact is actually in the reactor projects. If
     * true a virtual dependency is created based on the evidence in the
     * project.
     *
     * @param engine a reference to the engine being used to scan
     * @param artifact the artifact being analyzed in the mojo
     * @param depender The project that depends on this virtual dependency
     * @return <code>true</code> if the artifact is a snapshot artifact in the
     * reactor; otherwise <code>false</code>
     */
    private boolean addSnapshotReactorDependency(Engine engine, Artifact artifact, final MavenProject depender) {
        if (!artifact.isSnapshot()) {
            return false;
        }
        return addVirtualDependencyFromReactor(engine, artifact, depender, "Found snapshot reactor project in aggregate for %s - "
                + "creating a virtual dependency as the snapshot found in the repository may contain outdated dependencies.");
    }

    /**
     * @param project The target project to create a building request for.
     * @param repos the artifact repositories to use.
     * @return Returns a new ProjectBuildingRequest populated from the current
     * session and the target project remote repositories, used to resolve
     * artifacts.
     */
    public ProjectBuildingRequest newResolveArtifactProjectBuildingRequest(MavenProject project, List<ArtifactRepository> repos) {
        final ProjectBuildingRequest buildingRequest = new DefaultProjectBuildingRequest(session.getProjectBuildingRequest());
        buildingRequest.setRemoteRepositories(repos);
        buildingRequest.setProject(project);
        return buildingRequest;
    }

    /**
     * Executes the dependency-check scan and generates the necessary report.
     *
     * @throws MojoExecutionException thrown if there is an exception running
     * the scan
     * @throws MojoFailureException thrown if dependency-check is configured to
     * fail the build
     */
    protected void runCheck() throws MojoExecutionException, MojoFailureException {
        muteNoisyLoggers();
        try (Engine engine = initializeEngine()) {
            ExceptionCollection exCol = null;
            if (scanDependencies) {
                exCol = scanDependencies(engine);
            }
            if (scanPlugins) {
                exCol = scanPlugins(engine, exCol);
            }
            try {
                engine.analyzeDependencies();
            } catch (ExceptionCollection ex) {
                exCol = handleAnalysisExceptions(exCol, ex);
            }
            if (exCol == null || !exCol.isFatal()) {

                File outputDir = getCorrectOutputDirectory(this.getProject());
                if (outputDir == null) {
                    //in some regards we shouldn't be writing this, but we are anyway.
                    //we shouldn't write this because nothing is configured to generate this report.
                    outputDir = new File(this.getProject().getBuild().getDirectory());
                }
                try {
                    final MavenProject p = this.getProject();
                    for (String f : getFormats()) {
                        engine.writeReports(p.getName(), p.getGroupId(), p.getArtifactId(), p.getVersion(), outputDir, f, exCol);
                    }
                } catch (ReportException ex) {
                    if (exCol == null) {
                        exCol = new ExceptionCollection(ex);
                    } else {
                        exCol.addException(ex);
                    }
                    if (this.isFailOnError()) {
                        throw new MojoExecutionException("One or more exceptions occurred during dependency-check analysis", exCol);
                    } else {
                        getLog().debug("Error writing the report", ex);
                    }
                }
                showSummary(this.getProject(), engine.getDependencies());
                checkForFailure(engine.getDependencies());
                if (exCol != null && this.isFailOnError()) {
                    throw new MojoExecutionException("One or more exceptions occurred during dependency-check analysis", exCol);
                }
            }
        } catch (DatabaseException ex) {
            if (getLog().isDebugEnabled()) {
                getLog().debug("Database connection error", ex);
            }
            final String msg = "An exception occurred connecting to the local database. Please see the log file for more details.";
            if (this.isFailOnError()) {
                throw new MojoExecutionException(msg, ex);
            }
            getLog().error(msg, ex);
        } finally {
            getSettings().cleanup();
        }
    }

    /**
     * Combines the two exception collections and if either are fatal, throw an
     * MojoExecutionException
     *
     * @param currentEx the primary exception collection
     * @param newEx the new exception collection to add
     * @return the combined exception collection
     * @throws MojoExecutionException thrown if dependency-check is configured
     * to fail on errors
     */
    private ExceptionCollection handleAnalysisExceptions(ExceptionCollection currentEx, ExceptionCollection newEx) throws MojoExecutionException {
        ExceptionCollection returnEx = currentEx;
        if (returnEx == null) {
            returnEx = newEx;
        } else {
            returnEx.getExceptions().addAll(newEx.getExceptions());
            if (newEx.isFatal()) {
                returnEx.setFatal(true);
            }
        }
        if (returnEx.isFatal()) {
            final String msg = String.format("Fatal exception(s) analyzing %s", getProject().getName());
            if (this.isFailOnError()) {
                throw new MojoExecutionException(msg, returnEx);
            }
            getLog().error(msg);
            if (getLog().isDebugEnabled()) {
                getLog().debug(returnEx);
            }
        } else {
            final String msg = String.format("Exception(s) analyzing %s", getProject().getName());
            if (getLog().isDebugEnabled()) {
                getLog().debug(msg, returnEx);
            }
        }
        return returnEx;
    }

    /**
     * Scans the dependencies of the projects.
     *
     * @param engine the engine used to perform the scanning
     * @return a collection of exceptions
     * @throws MojoExecutionException thrown if a fatal exception occurs
     */
    protected abstract ExceptionCollection scanDependencies(Engine engine) throws MojoExecutionException;

    /**
     * Scans the plugins of the projects.
     *
     * @param engine the engine used to perform the scanning
     * @param exCol the collection of any exceptions that have previously been
     * captured.
     * @return a collection of exceptions
     * @throws MojoExecutionException thrown if a fatal exception occurs
     */
    protected abstract ExceptionCollection scanPlugins(Engine engine, ExceptionCollection exCol) throws MojoExecutionException;

    /**
     * Returns the report output directory.
     *
     * @return the report output directory
     */
    @Override
    public File getReportOutputDirectory() {
        return reportOutputDirectory;
    }

    /**
     * Sets the Reporting output directory.
     *
     * @param directory the output directory
     */
    @Override
    public void setReportOutputDirectory(File directory) {
        reportOutputDirectory = directory;
    }

    /**
     * Returns the output directory.
     *
     * @return the output directory
     */
    public File getOutputDirectory() {
        return outputDirectory;
    }

    /**
     * Returns whether this is an external report. This method always returns
     * true.
     *
     * @return <code>true</code>
     */
    @Override
    public final boolean isExternalReport() {
        return true;
    }

    /**
     * Returns the output name.
     *
     * @return the output name
     */
    @Override
    public String getOutputName() {
        final Set<String> selectedFormats = getFormats();
        if (selectedFormats.contains("HTML") || selectedFormats.contains("ALL") || selectedFormats.size() > 1) {
            return "dependency-check-report";
        } else if (selectedFormats.contains("JENKINS")) {
            return "dependency-check-jenkins.html";
        } else if (selectedFormats.contains("XML")) {
            return "dependency-check-report.xml";
        } else if (selectedFormats.contains("JUNIT")) {
            return "dependency-check-junit.xml";
        } else if (selectedFormats.contains("JSON")) {
            return "dependency-check-report.json";
        } else if (selectedFormats.contains("SARIF")) {
            return "dependency-check-report.sarif";
        } else if (selectedFormats.contains("CSV")) {
            return "dependency-check-report.csv";
        } else {
            getLog().warn("Unknown report format used during site generation.");
            return "dependency-check-report";
        }
    }

    /**
     * Returns the category name.
     *
     * @return the category name
     */
    @Override
    public String getCategoryName() {
        return MavenReport.CATEGORY_PROJECT_REPORTS;
    }
    //</editor-fold>

    /**
     * Initializes a new <code>Engine</code> that can be used for scanning. This
     * method should only be called in a try-with-resources to ensure that the
     * engine is properly closed.
     *
     * @return a newly instantiated <code>Engine</code>
     * @throws DatabaseException thrown if there is a database exception
     */
    protected Engine initializeEngine() throws DatabaseException {
        populateSettings();
        return new Engine(settings);
    }

    //CSOFF: MethodLength
    /**
     * Takes the properties supplied and updates the dependency-check settings.
     * Additionally, this sets the system properties required to change the
     * proxy URL, port, and connection timeout.
     */
    protected void populateSettings() {
        settings = new Settings();
        InputStream mojoProperties = null;
        try {
            mojoProperties = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE);
            settings.mergeProperties(mojoProperties);
        } catch (IOException ex) {
            getLog().warn("Unable to load the dependency-check maven mojo.properties file.");
            if (getLog().isDebugEnabled()) {
                getLog().debug("", ex);
            }
        } finally {
            if (mojoProperties != null) {
                try {
                    mojoProperties.close();
                } catch (IOException ex) {
                    if (getLog().isDebugEnabled()) {
                        getLog().debug("", ex);
                    }
                }
            }
        }
        settings.setStringIfNotEmpty(Settings.KEYS.MAVEN_LOCAL_REPO, mavenSettings.getLocalRepository());
        settings.setBooleanIfNotNull(Settings.KEYS.AUTO_UPDATE, autoUpdate);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED, enableExperimental);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIRED_ENABLED, enableRetired);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_GOLANG_DEP_ENABLED, golangDepEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_GOLANG_MOD_ENABLED, golangModEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_DART_ENABLED, dartAnalyzerEnabled);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_GOLANG_PATH, pathToGo);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_YARN_PATH, pathToYarn);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_PNPM_PATH, pathToPnpm);

        // use global maven proxy if provided
        final Proxy mavenProxy = getMavenProxy();
        if (mavenProxy != null) {
            final String existing = System.getProperty("https.proxyHost");
            if (existing == null && mavenProxy.getHost() != null && !mavenProxy.getHost().isEmpty()) {
                System.setProperty("https.proxyHost", mavenProxy.getHost());
                if (mavenProxy.getPort() > 0) {
                    System.setProperty("https.proxyPort", String.valueOf(mavenProxy.getPort()));
                }
                if (mavenProxy.getUsername() != null && !mavenProxy.getUsername().isEmpty()) {
                    System.setProperty("https.proxyUser", mavenProxy.getUsername());
                }
                if (mavenProxy.getPassword() != null && !mavenProxy.getPassword().isEmpty()) {
                    System.setProperty("https.proxyPassword", mavenProxy.getPassword());
                }
                if (mavenProxy.getNonProxyHosts() != null && !mavenProxy.getNonProxyHosts().isEmpty()) {
                    System.setProperty("http.nonProxyHosts", mavenProxy.getNonProxyHosts());
                }
            }

            settings.setString(Settings.KEYS.PROXY_SERVER, mavenProxy.getHost());
            settings.setString(Settings.KEYS.PROXY_PORT, Integer.toString(mavenProxy.getPort()));
            final String userName = mavenProxy.getUsername();
            String password = mavenProxy.getPassword();
            if (password != null && !password.isEmpty()) {
                if (settings.getBoolean(Settings.KEYS.PROXY_DISABLE_SCHEMAS, true)) {
                    System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
                }
                try {
                    password = decryptPasswordFromSettings(password);
                } catch (SecDispatcherException ex) {
                    password = handleSecDispatcherException("proxy", mavenProxy.getId(), password, ex);
                }
            }
            settings.setStringIfNotNull(Settings.KEYS.PROXY_USERNAME, userName);
            settings.setStringIfNotNull(Settings.KEYS.PROXY_PASSWORD, password);
            settings.setStringIfNotNull(Settings.KEYS.PROXY_NON_PROXY_HOSTS, mavenProxy.getNonProxyHosts());
        } else if (System.getProperty("http.proxyHost") != null) {
            //else use standard Java system properties
            settings.setString(Settings.KEYS.PROXY_SERVER, System.getProperty("http.proxyHost", ""));
            if (System.getProperty("http.proxyPort") != null) {
                settings.setString(Settings.KEYS.PROXY_PORT, System.getProperty("http.proxyPort"));
            }
            if (System.getProperty("http.proxyUser") != null) {
                settings.setString(Settings.KEYS.PROXY_USERNAME, System.getProperty("http.proxyUser"));
            }
            if (System.getProperty("http.proxyPassword") != null) {
                settings.setString(Settings.KEYS.PROXY_PASSWORD, System.getProperty("http.proxyPassword"));
            }
            if (System.getProperty("http.nonProxyHosts") != null) {
                settings.setString(Settings.KEYS.PROXY_NON_PROXY_HOSTS, System.getProperty("http.nonProxyHosts"));
            }
        } else if (this.proxy != null && this.proxy.getHost() != null) {
            // or use configured <proxy>
            settings.setString(Settings.KEYS.PROXY_SERVER, this.proxy.getHost());
            settings.setString(Settings.KEYS.PROXY_PORT, Integer.toString(this.proxy.getPort()));
            // user name and password from <server> entry settings.xml
            configureServerCredentials(this.proxy.getServerId(), Settings.KEYS.PROXY_USERNAME, Settings.KEYS.PROXY_PASSWORD);
        }

        final String[] suppressions = determineSuppressions();
        settings.setArrayIfNotEmpty(Settings.KEYS.SUPPRESSION_FILE, suppressions);
        settings.setBooleanIfNotNull(Settings.KEYS.UPDATE_VERSION_CHECK_ENABLED, versionCheckEnabled);
        settings.setStringIfNotEmpty(Settings.KEYS.CONNECTION_TIMEOUT, connectionTimeout);
        settings.setStringIfNotEmpty(Settings.KEYS.CONNECTION_READ_TIMEOUT, readTimeout);
        settings.setStringIfNotEmpty(Settings.KEYS.HINTS_FILE, hintsFile);
        settings.setFloat(Settings.KEYS.JUNIT_FAIL_ON_CVSS, junitFailOnCVSS);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_JAR_ENABLED, jarAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NUSPEC_ENABLED, nuspecAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NUGETCONF_ENABLED, nugetconfAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_LIBMAN_ENABLED, libmanAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, centralAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_CENTRAL_USE_CACHE, centralAnalyzerUseCache);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_ENABLED, artifactoryAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NEXUS_ENABLED, nexusAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED, assemblyAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_MSBUILD_PROJECT_ENABLED, msbuildAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, archiveAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_KNOWN_EXPLOITED_ENABLED, knownExploitedEnabled);
        settings.setStringIfNotEmpty(Settings.KEYS.KEV_URL, knownExploitedUrl);
        settings.setStringIfNotEmpty(Settings.KEYS.ADDITIONAL_ZIP_EXTENSIONS, zipExtensions);
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_ASSEMBLY_DOTNET_PATH, pathToCore);
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_NEXUS_URL, nexusUrl);
        configureServerCredentials(nexusServerId, Settings.KEYS.ANALYZER_NEXUS_USER, Settings.KEYS.ANALYZER_NEXUS_PASSWORD);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NEXUS_USES_PROXY, nexusUsesProxy);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_URL, artifactoryAnalyzerUrl);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_USES_PROXY, artifactoryAnalyzerUseProxy);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_PARALLEL_ANALYSIS, artifactoryAnalyzerParallelAnalysis);
        if (Boolean.TRUE.equals(artifactoryAnalyzerEnabled)) {
            if (artifactoryAnalyzerServerId != null) {
                configureServerCredentials(artifactoryAnalyzerServerId, Settings.KEYS.ANALYZER_ARTIFACTORY_API_USERNAME,
                        Settings.KEYS.ANALYZER_ARTIFACTORY_API_TOKEN);
            } else {
                settings.setStringIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_API_USERNAME, artifactoryAnalyzerUsername);
                settings.setStringIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_API_TOKEN, artifactoryAnalyzerApiToken);
            }
            settings.setStringIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_BEARER_TOKEN, artifactoryAnalyzerBearerToken);
        }
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED, pyDistributionAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_PYTHON_PACKAGE_ENABLED, pyPackageAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_RUBY_GEMSPEC_ENABLED, rubygemsAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_OPENSSL_ENABLED, opensslAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_CMAKE_ENABLED, cmakeAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_AUTOCONF_ENABLED, autoconfAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_MAVEN_INSTALL_ENABLED, mavenInstallAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_PIP_ENABLED, pipAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_PIPFILE_ENABLED, pipfileAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_POETRY_ENABLED, poetryAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_COMPOSER_LOCK_ENABLED, composerAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_CPANFILE_ENABLED, cpanfileAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED, nodeAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED, nodeAuditAnalyzerEnabled);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_NODE_AUDIT_URL, nodeAuditAnalyzerUrl);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_AUDIT_USE_CACHE, nodeAuditAnalyzerUseCache);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_PACKAGE_SKIPDEV, nodePackageSkipDevDependencies);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_AUDIT_SKIPDEV, nodeAuditSkipDevDependencies);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_YARN_AUDIT_ENABLED, yarnAuditAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_PNPM_AUDIT_ENABLED, pnpmAuditAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, retireJsAnalyzerEnabled);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, retireJsUrl);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_FORCEUPDATE, retireJsForceUpdate);
        if (retireJsUser == null && retireJsPassword == null && retireJsUrlServerId != null) {
            configureServerCredentials(retireJsUrlServerId, Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_USER, Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_PASSWORD);
        } else {
            settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_USER, retireJsUser);
            settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_PASSWORD, retireJsPassword);
        }
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_MIX_AUDIT_ENABLED, mixAuditAnalyzerEnabled);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_MIX_AUDIT_PATH, mixAuditPath);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_ENABLED, bundleAuditAnalyzerEnabled);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_PATH, bundleAuditPath);
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_WORKING_DIRECTORY, bundleAuditWorkingDirectory);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_COCOAPODS_ENABLED, cocoapodsAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_CARTHAGE_ENABLED, carthageAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED, swiftPackageManagerAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_SWIFT_PACKAGE_RESOLVED_ENABLED, swiftPackageResolvedAnalyzerEnabled);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, ossindexAnalyzerEnabled);
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_OSSINDEX_URL, ossindexAnalyzerUrl);
        configureServerCredentials(ossIndexServerId, Settings.KEYS.ANALYZER_OSSINDEX_USER, Settings.KEYS.ANALYZER_OSSINDEX_PASSWORD);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_OSSINDEX_USE_CACHE, ossindexAnalyzerUseCache);
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_OSSINDEX_WARN_ONLY_ON_REMOTE_ERRORS, ossIndexWarnOnlyOnRemoteErrors);
        if (retirejs != null) {
            settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_FILTER_NON_VULNERABLE, retirejs.getFilterNonVulnerable());
            settings.setArrayIfNotEmpty(Settings.KEYS.ANALYZER_RETIREJS_FILTERS, retirejs.getFilters());
        }
        //Database configuration
        settings.setStringIfNotEmpty(Settings.KEYS.DB_DRIVER_NAME, databaseDriverName);
        settings.setStringIfNotEmpty(Settings.KEYS.DB_DRIVER_PATH, databaseDriverPath);
        settings.setStringIfNotEmpty(Settings.KEYS.DB_CONNECTION_STRING, connectionString);
        if (databaseUser == null && databasePassword == null && serverId != null) {
            configureServerCredentials(serverId, Settings.KEYS.DB_USER, Settings.KEYS.DB_PASSWORD);
        } else {
            settings.setStringIfNotEmpty(Settings.KEYS.DB_USER, databaseUser);
            settings.setStringIfNotEmpty(Settings.KEYS.DB_PASSWORD, databasePassword);
        }
        settings.setStringIfNotEmpty(Settings.KEYS.DATA_DIRECTORY, dataDirectory);
        settings.setStringIfNotEmpty(Settings.KEYS.DB_FILE_NAME, dbFilename);
        settings.setStringIfNotNull(Settings.KEYS.NVD_API_ENDPOINT, nvdApiEndpoint);
        settings.setIntIfNotNull(Settings.KEYS.NVD_API_DELAY, nvdApiDelay);
        settings.setIntIfNotNull(Settings.KEYS.NVD_API_RESULTS_PER_PAGE, nvdApiResultsPerPage);
        settings.setStringIfNotEmpty(Settings.KEYS.NVD_API_DATAFEED_URL, nvdDatafeedUrl);
        settings.setIntIfNotNull(Settings.KEYS.NVD_API_VALID_FOR_HOURS, nvdValidForHours);
        settings.setIntIfNotNull(Settings.KEYS.NVD_API_MAX_RETRY_COUNT, nvdMaxRetryCount);
        if (nvdApiKey == null) {
            if (nvdApiKeyEnvironmentVariable != null) {
                settings.setStringIfNotEmpty(Settings.KEYS.NVD_API_KEY, System.getenv(nvdApiKeyEnvironmentVariable));
                getLog().debug("Using NVD API key from environment variable " + nvdApiKeyEnvironmentVariable);
            } else if (nvdApiServerId != null) {
                configureServerCredentialsApiKey(nvdApiServerId, Settings.KEYS.NVD_API_KEY);
                getLog().debug("Using NVD API key from server's password with id " + nvdApiServerId + " in settings.xml");
            }
        } else {
            settings.setStringIfNotEmpty(Settings.KEYS.NVD_API_KEY, nvdApiKey);
        }
        if (nvdUser == null && nvdPassword == null && nvdDatafeedServerId != null) {
            configureServerCredentials(nvdDatafeedServerId, Settings.KEYS.NVD_API_DATAFEED_USER, Settings.KEYS.NVD_API_DATAFEED_PASSWORD);
        } else {
            settings.setStringIfNotEmpty(Settings.KEYS.NVD_API_DATAFEED_USER, nvdUser);
            settings.setStringIfNotEmpty(Settings.KEYS.NVD_API_DATAFEED_PASSWORD, nvdPassword);
        }
        settings.setBooleanIfNotNull(Settings.KEYS.PRETTY_PRINT, prettyPrint);
        artifactScopeExcluded = new ArtifactScopeExcluded(skipTestScope, skipProvidedScope, skipSystemScope, skipRuntimeScope);
        artifactTypeExcluded = new ArtifactTypeExcluded(skipArtifactType);
        if (suppressionFileUser == null && suppressionFilePassword == null && suppressionFileServerId != null) {
            configureServerCredentials(suppressionFileServerId, Settings.KEYS.SUPPRESSION_FILE_USER, Settings.KEYS.SUPPRESSION_FILE_PASSWORD);
        } else {
            settings.setStringIfNotEmpty(Settings.KEYS.SUPPRESSION_FILE_USER, suppressionFileUser);
            settings.setStringIfNotEmpty(Settings.KEYS.SUPPRESSION_FILE_PASSWORD, suppressionFilePassword);
        }
        settings.setIntIfNotNull(Settings.KEYS.HOSTED_SUPPRESSIONS_VALID_FOR_HOURS, hostedSuppressionsValidForHours);
        settings.setStringIfNotNull(Settings.KEYS.HOSTED_SUPPRESSIONS_URL, hostedSuppressionsUrl);
        settings.setBooleanIfNotNull(Settings.KEYS.HOSTED_SUPPRESSIONS_FORCEUPDATE, hostedSuppressionsForceUpdate);
        settings.setBooleanIfNotNull(Settings.KEYS.HOSTED_SUPPRESSIONS_ENABLED, hostedSuppressionsEnabled);
    }
    //CSON: MethodLength

    /**
     * Retrieves the server credentials from the settings.xml, decrypts the
     * password, and places the values into the settings under the given key
     * names.
     *
     * @param serverId the server id
     * @param userSettingKey the property name for the username
     * @param passwordSettingKey the property name for the password
     */
    private void configureServerCredentials(String serverId, String userSettingKey, String passwordSettingKey) {
        if (serverId != null) {
            final Server server = settingsXml.getServer(serverId);
            if (server != null) {
                final String username = server.getUsername();
                String password = null;
                try {
                    password = decryptPasswordFromSettings(server.getPassword());
                } catch (SecDispatcherException ex) {
                    password = handleSecDispatcherException("server", serverId, server.getPassword(), ex);
                }
                settings.setStringIfNotEmpty(userSettingKey, username);
                settings.setStringIfNotEmpty(passwordSettingKey, password);
            } else {
                getLog().error(String.format("Server '%s' not found in the settings.xml file", serverId));
            }
        }
    }

    /**
     * Retrieves the server credentials from the settings.xml, decrypts the
     * password, and places the values into the settings under the given key
     * names. This is used to retrieve an encrypted password as an API key.
     *
     * @param serverId the server id
     * @param apiKeySetting the property name for the API key
     */
    private void configureServerCredentialsApiKey(String serverId, String apiKeySetting) {
        if (serverId != null) {
            final Server server = settingsXml.getServer(serverId);
            if (server != null) {
                String password = null;
                try {
                    password = decryptPasswordFromSettings(server.getPassword());
                } catch (SecDispatcherException ex) {
                    password = handleSecDispatcherException("server", serverId, server.getPassword(), ex);
                }
                settings.setStringIfNotEmpty(apiKeySetting, password);
            } else {
                getLog().error(String.format("Server '%s' not found in the settings.xml file", serverId));
            }
        }
    }

    /**
     * Decrypts a password from the Maven settings if it needs to be decrypted.
     * If it's not encrypted the input password will be returned unchanged.
     *
     * @param password the original password value from the settings.xml
     * @return the decrypted password from the Maven configuration
     * @throws SecDispatcherException thrown if there is an error decrypting the
     * password
     */
    private String decryptPasswordFromSettings(String password) throws SecDispatcherException {
        //The following fix was copied from:
        //   https://github.com/bsorrentino/maven-confluence-plugin/blob/master/maven-confluence-reporting-plugin/src/main/java/org/bsc/maven/confluence/plugin/AbstractBaseConfluenceMojo.java
        //
        // FIX to resolve
        // org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException:
        // java.io.FileNotFoundException: ~/.settings-security.xml (No such file or directory)
        //
        if (securityDispatcher instanceof DefaultSecDispatcher) {
            ((DefaultSecDispatcher) securityDispatcher).setConfigurationFile("~/.m2/settings-security.xml");
        }

        return securityDispatcher.decrypt(password);
    }

    /**
     * Handles a SecDispatcherException that was thrown at an attempt to decrypt
     * an encrypted password from the Maven settings.
     *
     * @param settingsElementName - "server" or "proxy"
     * @param settingsElementId - value of the id attribute of the proxy resp.
     * server element to which the password belongs
     * @param passwordValueFromSettings - original, undecrypted password value
     * from the settings
     * @param ex - the Exception to handle
     * @return the password fallback value to go on with, might be a not working
     * one.
     */
    private String handleSecDispatcherException(String settingsElementName, String settingsElementId, String passwordValueFromSettings,
            SecDispatcherException ex) {
        String password = passwordValueFromSettings;
        if (ex.getCause() instanceof FileNotFoundException
                || (ex.getCause() != null && ex.getCause().getCause() instanceof FileNotFoundException)) {
            //maybe its not encrypted?
            final String tmp = passwordValueFromSettings;
            if (tmp.startsWith("{") && tmp.endsWith("}")) {
                getLog().error(String.format(
                        "Unable to decrypt the %s password for %s id '%s' in settings.xml%n\tCause: %s",
                        settingsElementName, settingsElementName, settingsElementId, ex.getMessage()));
            } else {
                password = tmp;
            }
        } else {
            getLog().error(String.format(
                    "Unable to decrypt the %s password for %s id '%s' in settings.xml%n\tCause: %s",
                    settingsElementName, settingsElementName, settingsElementId, ex.getMessage()));
        }
        return password;
    }

    /**
     * Combines the configured suppressionFile and suppressionFiles into a
     * single array.
     *
     * @return an array of suppression file paths
     */
    private String[] determineSuppressions() {
        String[] suppressions = suppressionFiles;
        if (suppressionFile != null) {
            if (suppressions == null) {
                suppressions = new String[]{suppressionFile};
            } else {
                suppressions = Arrays.copyOf(suppressions, suppressions.length + 1);
                suppressions[suppressions.length - 1] = suppressionFile;
            }
        }
        return suppressions;
    }

    /**
     * Hacky method of muting the noisy logging from JCS
     */
    private void muteNoisyLoggers() {
        System.setProperty("jcs.logSystem", "slf4j");
        if (!getLog().isDebugEnabled()) {
            Slf4jAdapter.muteLogging(true);
        }

        final String[] noisyLoggers = {
            "org.apache.hc"
        };
        for (String loggerName : noisyLoggers) {
            System.setProperty("org.slf4j.simpleLogger.log." + loggerName, "error");
        }
    }

    /**
     * Returns the maven proxy.
     *
     * @return the maven proxy
     */
    private Proxy getMavenProxy() {
        if (mavenSettings != null) {
            final List<Proxy> proxies = mavenSettings.getProxies();
            if (proxies != null && !proxies.isEmpty()) {
                if (mavenSettingsProxyId != null) {
                    for (Proxy proxy : proxies) {
                        if (mavenSettingsProxyId.equalsIgnoreCase(proxy.getId())) {
                            return proxy;
                        }
                    }
                } else {
                    for (Proxy aProxy : proxies) {
                        if (aProxy.isActive()) {
                            return aProxy;
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * Returns a reference to the current project. This method is used instead
     * of auto-binding the project via component annotation in concrete
     * implementations of this. If the child has a
     * <code>@Component MavenProject project;</code> defined then the abstract
     * class (i.e. this class) will not have access to the current project (just
     * the way Maven works with the binding).
     *
     * @return returns a reference to the current project
     */
    protected MavenProject getProject() {
        return project;
    }

    /**
     * Returns the list of Maven Projects in this build.
     *
     * @return the list of Maven Projects in this build
     */
    protected List<MavenProject> getReactorProjects() {
        return reactorProjects;
    }

    /**
     * Combines the format and formats properties into a single collection.
     *
     * @return the selected report formats
     */
    private Set<String> getFormats() {
        final Set<String> invalid = new HashSet<>();
        final Set<String> selectedFormats = formats == null || formats.length == 0 ? new HashSet<>() : new HashSet<>(Arrays.asList(formats));
        selectedFormats.forEach((s) -> {
            try {
                ReportGenerator.Format.valueOf(s.toUpperCase());
            } catch (IllegalArgumentException ex) {
                invalid.add(s);
            }
        });
        invalid.forEach((s) -> getLog().warn("Invalid report format specified: " + s));
        if (selectedFormats.contains("true")) {
            selectedFormats.remove("true");
        }
        if (format != null && selectedFormats.isEmpty()) {
            selectedFormats.add(format);
        }
        return selectedFormats;
    }

    /**
     * Returns the list of excluded artifacts based on either artifact id or
     * group id and artifact id.
     *
     * @return a list of artifact to exclude
     */
    public List<String> getExcludes() {
        if (excludes == null) {
            excludes = new ArrayList<>();
        }
        return excludes;
    }

    /**
     * Returns the artifact scope excluded filter.
     *
     * @return the artifact scope excluded filter
     */
    protected Filter<String> getArtifactScopeExcluded() {
        return artifactScopeExcluded;
    }

    /**
     * Returns the configured settings.
     *
     * @return the configured settings
     */
    protected Settings getSettings() {
        return settings;
    }

    //<editor-fold defaultstate="collapsed" desc="Methods to fail build or show summary">
    /**
     * Checks to see if a vulnerability has been identified with a CVSS score
     * that is above the threshold set in the configuration.
     *
     * @param dependencies the list of dependency objects
     * @throws MojoFailureException thrown if a CVSS score is found that is
     * higher then the threshold set
     */
    protected void checkForFailure(Dependency[] dependencies) throws MojoFailureException {
        final StringBuilder ids = new StringBuilder();
        for (Dependency d : dependencies) {
            boolean addName = true;
            for (Vulnerability v : d.getVulnerabilities()) {
                final Double cvssV2 = v.getCvssV2() != null && v.getCvssV2().getCvssData() != null && v.getCvssV2().getCvssData().getBaseScore() != null ? v.getCvssV2().getCvssData().getBaseScore() : -1;
                final Double cvssV3 = v.getCvssV3() != null && v.getCvssV3().getCvssData() != null && v.getCvssV3().getCvssData().getBaseScore() != null ? v.getCvssV3().getCvssData().getBaseScore() : -1;
                final Double unscoredCvss = v.getUnscoredSeverity() != null ? SeverityUtil.estimateCvssV2(v.getUnscoredSeverity()) : -1;

                if (failBuildOnAnyVulnerability || cvssV2 >= failBuildOnCVSS
                        || cvssV3 >= failBuildOnCVSS
                        || unscoredCvss >= failBuildOnCVSS
                        //safety net to fail on any if for some reason the above misses on 0
                        || (failBuildOnCVSS <= 0.0)) {
                    String name = v.getName();
                    if (cvssV3 >= 0.0) {
                        name += "(" + cvssV3 + ")";
                    } else if (cvssV2 >= 0.0) {
                        name += "(" + cvssV2 + ")";
                    } else if (unscoredCvss >= 0.0) {
                        name += "(" + unscoredCvss + ")";
                    }
                    if (addName) {
                        addName = false;
                        ids.append(NEW_LINE).append(d.getFileName()).append(": ");
                        ids.append(name);
                    } else {
                        ids.append(", ").append(name);
                    }
                }
            }
        }
        if (ids.length() > 0) {
            final String msg;
            if (showSummary) {
                if (failBuildOnAnyVulnerability) {
                    msg = String.format("%n%nOne or more dependencies were identified with vulnerabilities: %n%s%n%n"
                            + "See the dependency-check report for more details.%n%n", ids);
                } else {
                    msg = String.format("%n%nOne or more dependencies were identified with vulnerabilities that have a CVSS score greater than or "
                            + "equal to '%.1f': %n%s%n%nSee the dependency-check report for more details.%n%n", failBuildOnCVSS, ids);
                }
            } else {
                msg = String.format("%n%nOne or more dependencies were identified with vulnerabilities.%n%n"
                        + "See the dependency-check report for more details.%n%n");
            }
            throw new MojoFailureException(msg);
        }
    }

    /**
     * Generates a warning message listing a summary of dependencies and their
     * associated CPE and CVE entries.
     *
     * @param mp the Maven project for which the summary is shown
     * @param dependencies a list of dependency objects
     */
    protected void showSummary(MavenProject mp, Dependency[] dependencies) {
        if (showSummary) {
            DependencyCheckScanAgent.showSummary(mp.getName(), dependencies);
        }
    }

    //</editor-fold>
    //CSOFF: ParameterNumber
    private ExceptionCollection scanDependencyNode(DependencyNode dependencyNode, DependencyNode root,
            Engine engine, MavenProject project, List<ArtifactResult> allResolvedDeps,
            ProjectBuildingRequest buildingRequest, boolean aggregate, ExceptionCollection exceptionCollection) {
        ExceptionCollection exCol = exceptionCollection;
        if (artifactScopeExcluded.passes(dependencyNode.getArtifact().getScope())
                || artifactTypeExcluded.passes(dependencyNode.getArtifact().getType())) {
            return exCol;
        }

        boolean isResolved = false;
        File artifactFile = null;
        String artifactId = null;
        String groupId = null;
        String version = null;
        List<ArtifactVersion> availableVersions = null;
        if (org.apache.maven.artifact.Artifact.SCOPE_SYSTEM.equals(dependencyNode.getArtifact().getScope())) {
            final Artifact a = dependencyNode.getArtifact();
            if (a.isResolved() && a.getFile().isFile()) {
                artifactFile = a.getFile();
                isResolved = artifactFile.isFile();
                groupId = a.getGroupId();
                artifactId = a.getArtifactId();
                version = a.getVersion();
                availableVersions = a.getAvailableVersions();
            } else {
                for (org.apache.maven.model.Dependency d : project.getDependencies()) {
                    if (d.getSystemPath() != null && artifactsMatch(d, a)) {
                        artifactFile = new File(d.getSystemPath());
                        isResolved = artifactFile.isFile();
                        groupId = a.getGroupId();
                        artifactId = a.getArtifactId();
                        version = a.getVersion();
                        availableVersions = a.getAvailableVersions();
                        break;
                    }
                }
            }
            Throwable ignored = null;
            if (!isResolved) {
                // Issue #4969 Tycho appears to add System-scoped libraries in reactor projects in unresolved state
                // so attempt to do a resolution for system-scoped too if still nothing found
                try {
                    tryResolutionOnce(project, allResolvedDeps, buildingRequest);
                    final Artifact result = findInAllDeps(allResolvedDeps, dependencyNode.getArtifact(), project);
                    isResolved = result.isResolved();
                    artifactFile = result.getFile();
                    groupId = result.getGroupId();
                    artifactId = result.getArtifactId();
                    version = result.getVersion();
                    availableVersions = result.getAvailableVersions();
                } catch (DependencyNotFoundException | DependencyResolverException e) {
                    getLog().warn("Error performing last-resort System-scoped dependency resolution: " + e.getMessage());
                    ignored = e;
                }
            }
            if (!isResolved) {
                final StringBuilder message = new StringBuilder("Unable to resolve system scoped dependency: ");
                if (artifactFile != null) {
                    message.append(dependencyNode.toNodeString()).append(" at path ").append(artifactFile);
                } else {
                    message.append(dependencyNode.toNodeString()).append(" at path ").append(a.getFile());
                }
                getLog().error(message);
                if (exCol == null) {
                    exCol = new ExceptionCollection();
                }
                final Exception thrown = new DependencyNotFoundException(message.toString());
                if (ignored != null) {
                    thrown.addSuppressed(ignored);
                }
                exCol.addException(thrown);
            }
        } else {
            final Artifact dependencyArtifact = dependencyNode.getArtifact();
            final Artifact result;
            if (dependencyArtifact.isResolved()) {
                //All transitive dependencies, excluding reactor and dependencyManagement artifacts should
                //have been resolved by Maven prior to invoking the plugin - resolving the dependencies
                //manually is unnecessary, and does not work in some cases (issue-1751)
                getLog().debug(String.format("Skipping artifact %s, already resolved", dependencyArtifact.getArtifactId()));
                result = dependencyArtifact;
            } else {
                try {
                    tryResolutionOnce(project, allResolvedDeps, buildingRequest);
                    result = findInAllDeps(allResolvedDeps, dependencyNode.getArtifact(), project);
                } catch (DependencyNotFoundException | DependencyResolverException ex) {
                    getLog().debug(String.format("Aggregate : %s", aggregate));
                    boolean addException = true;
                    //CSOFF: EmptyBlock
                    if (!aggregate) {
                        // do nothing - the exception is to be reported
                    } else if (addReactorDependency(engine, dependencyNode.getArtifact(), project)) {
                        // successfully resolved as a reactor dependency - swallow the exception
                        addException = false;
                    }
                    if (addException) {
                        if (exCol == null) {
                            exCol = new ExceptionCollection();
                        }
                        exCol.addException(ex);
                    }
                    return exCol;
                }
            }
            if (aggregate && virtualSnapshotsFromReactor
                    && dependencyNode.getArtifact().isSnapshot()
                    && addSnapshotReactorDependency(engine, dependencyNode.getArtifact(), project)) {
                return exCol;
            }
            isResolved = result.isResolved();
            artifactFile = result.getFile();
            groupId = result.getGroupId();
            artifactId = result.getArtifactId();
            version = result.getVersion();
            availableVersions = result.getAvailableVersions();
        }
        if (isResolved && artifactFile != null) {
            final List<Dependency> deps = engine.scan(artifactFile.getAbsoluteFile(),
                    createProjectReferenceName(project, dependencyNode));
            if (deps != null) {
                processResolvedArtifact(artifactFile, deps, groupId, artifactId, version, root, project, availableVersions, dependencyNode);
            } else if ("import".equals(dependencyNode.getArtifact().getScope())) {
                final String msg = String.format("Skipping '%s:%s' in project %s as it uses an `import` scope",
                        dependencyNode.getArtifact().getId(), dependencyNode.getArtifact().getScope(), project.getName());
                getLog().debug(msg);
            } else if ("pom".equals(dependencyNode.getArtifact().getType())) {
                exCol = processPomArtifact(artifactFile, root, project, engine, exCol);
            } else {
                if (!scannedFiles.contains(artifactFile)) {
                    final String msg = String.format("No analyzer could be found or the artifact has been scanned twice for '%s:%s' in project %s",
                            dependencyNode.getArtifact().getId(), dependencyNode.getArtifact().getScope(), project.getName());
                    getLog().warn(msg);
                }
            }
        } else {
            final String msg = String.format("Unable to resolve '%s' in project %s",
                    dependencyNode.getArtifact().getId(), project.getName());
            getLog().debug(msg);
            if (exCol == null) {
                exCol = new ExceptionCollection();
            }
        }
        return exCol;
    }

    /**
     * Try resolution of artifacts once, allowing for
     * DependencyResolutionException due to reactor-dependencies not being
     * resolvable.
     * <br>
     * The resolution is attempted only if allResolvedDeps is still empty. The
     * assumption is that for any given project at least one of the dependencies
     * will successfully resolve. If not, resolution will be attempted once for
     * every dependency (as allResolvedDeps remains empty).
     *
     * @param project The project to dependencies for
     * @param allResolvedDeps The collection of successfully resolved
     * dependencies, will be filled with the successfully resolved dependencies,
     * even in case of resolution failures.
     * @param buildingRequest The buildingRequest to hand to Maven's
     * DependencyResolver.
     * @throws DependencyResolverException For any DependencyResolverException
     * other than an Eclipse Aether DependencyResolutionException
     */
    private void tryResolutionOnce(MavenProject project, List<ArtifactResult> allResolvedDeps, ProjectBuildingRequest buildingRequest) throws DependencyResolverException {
        if (allResolvedDeps.isEmpty()) { // no (partially successful) resolution attempt done
            try {
                final List<org.apache.maven.model.Dependency> dependencies = project.getDependencies();
                final List<org.apache.maven.model.Dependency> managedDependencies = project
                        .getDependencyManagement() == null ? null : project.getDependencyManagement().getDependencies();
                final Iterable<ArtifactResult> allDeps = dependencyResolver
                        .resolveDependencies(buildingRequest, dependencies, managedDependencies, null);
                allDeps.forEach(allResolvedDeps::add);
            } catch (DependencyResolverException dre) {
                if (dre.getCause() instanceof org.eclipse.aether.resolution.DependencyResolutionException) {
                    final List<ArtifactResult> successResults = Mshared998Util
                            .getResolutionResults((org.eclipse.aether.resolution.DependencyResolutionException) dre.getCause());
                    allResolvedDeps.addAll(successResults);
                } else {
                    throw dre;
                }
            }
        }
    }
    //CSON: ParameterNumber

    //CSOFF: ParameterNumber
    private void processResolvedArtifact(File artifactFile, final List<Dependency> deps,
            String groupId, String artifactId, String version, DependencyNode root,
            MavenProject project1, List<ArtifactVersion> availableVersions,
            DependencyNode dependencyNode) {
        scannedFiles.add(artifactFile);
        Dependency d = null;
        if (deps.size() == 1) {
            d = deps.get(0);

        } else {
            for (Dependency possible : deps) {
                if (artifactFile.getAbsoluteFile().equals(possible.getActualFile())) {
                    d = possible;
                    break;
                }
            }
            for (Dependency dep : deps) {
                if (d != null && d != dep) {
                    final String includedBy = buildReference(groupId, artifactId, version);
                    dep.addIncludedBy(includedBy);
                }
            }
        }
        if (d != null) {
            final MavenArtifact ma = new MavenArtifact(groupId, artifactId, version);
            d.addAsEvidence("pom", ma, Confidence.HIGHEST);
            if (root != null) {
                final String includedby = buildReference(
                        root.getArtifact().getGroupId(),
                        root.getArtifact().getArtifactId(),
                        root.getArtifact().getVersion());
                d.addIncludedBy(includedby);
            } else {
                final String includedby = buildReference(project1.getGroupId(), project1.getArtifactId(), project1.getVersion());
                d.addIncludedBy(includedby);
            }
            if (availableVersions != null) {
                for (ArtifactVersion av : availableVersions) {
                    d.addAvailableVersion(av.toString());
                }
            }
            getLog().debug(String.format("Adding project reference %s on dependency %s", project1.getName(), d.getDisplayFileName()));
        } else if (getLog().isDebugEnabled()) {
            final String msg = String.format("More than 1 dependency was identified in first pass scan of '%s' in project %s", dependencyNode.getArtifact().getId(), project1.getName());
            getLog().debug(msg);
        }
    }
    //CSON: ParameterNumber

    private ExceptionCollection processPomArtifact(File artifactFile, DependencyNode root,
            MavenProject project1, Engine engine, ExceptionCollection exCollection) {
        ExceptionCollection exCol = exCollection;
        try {
            final Dependency d = new Dependency(artifactFile.getAbsoluteFile());
            final Model pom = PomUtils.readPom(artifactFile.getAbsoluteFile());
            JarAnalyzer.setPomEvidence(d, pom, null, true);
            if (root != null) {
                final String includedby = buildReference(
                        root.getArtifact().getGroupId(),
                        root.getArtifact().getArtifactId(),
                        root.getArtifact().getVersion());
                d.addIncludedBy(includedby);
            } else {
                final String includedby = buildReference(project1.getGroupId(), project1.getArtifactId(), project1.getVersion());
                d.addIncludedBy(includedby);
            }
            engine.addDependency(d);
        } catch (AnalysisException ex) {
            if (exCol == null) {
                exCol = new ExceptionCollection();
            }
            exCol.addException(ex);
            getLog().debug("Error reading pom " + artifactFile.getAbsoluteFile(), ex);
        }
        return exCol;
    }

}
//CSON: FileLength
