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
 */
package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import java.io.FileFilter;
import java.util.List;

import javax.annotation.concurrent.ThreadSafe;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;

import com.moandjiezana.toml.Toml;
import java.io.File;
import java.util.Optional;

import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Checksum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Poetry dependency analyzer.
 *
 * @author Ferdinand Niedermann
 * @author Jeremy Long
 */
@ThreadSafe
@Experimental
public class PoetryAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(PoetryAnalyzer.class);

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.PYTHON;

    /**
     * Lock file name.
     */
    private static final String POETRY_LOCK = "poetry.lock";
    /**
     * Poetry project file.
     */
    private static final String PYPROJECT_TOML = "pyproject.toml";
    /**
     * The file filter for poetry.lock
     */
    private static final FileFilter POETRY_LOCK_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(POETRY_LOCK, PYPROJECT_TOML)
            .build();

    /**
     * Returns the name of the Poetry Analyzer.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return "Poetry Analyzer";
    }

    /**
     * Tell that we are used for information collection.
     *
     * @return INFORMATION_COLLECTION
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }

    /**
     * Returns the key name for the analyzers enabled setting.
     *
     * @return the key name for the analyzers enabled setting
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_POETRY_ENABLED;
    }

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return POETRY_LOCK_FILTER;
    }

    /**
     * No-op initializer implementation.
     *
     * @param engine a reference to the dependency-check engine
     *
     * @throws InitializationException never thrown
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        // Nothing to do here.
    }

    /**
     * Analyzes poetry packages and adds evidence to the dependency.
     *
     * @param dependency the dependency being analyzed
     * @param engine the engine being used to perform the scan
     *
     * @throws AnalysisException thrown if there is an unrecoverable error
     * analyzing the dependency
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        LOGGER.debug("Checking file {}", dependency.getActualFilePath());

        //do not report on the build file itself
        engine.removeDependency(dependency);

        final Optional<Toml> potentiallyParsedToml = parseDependencyFile(dependency);
        if (potentiallyParsedToml.isEmpty()) {
            LOGGER.warn("toml file skipped: {} could not be parsed", dependency.getActualFilePath());
            return;
        }
        final Toml result = potentiallyParsedToml.get();
        if (PYPROJECT_TOML.equals(dependency.getActualFile().getName())) {
            if (result.getTable("tool.poetry") == null) {
                LOGGER.debug("skipping {} as it does not contain `tool.poetry`", dependency.getDisplayFileName());
                return;
            }

            final File parentPath = dependency.getActualFile().getParentFile();
            ensureLock(parentPath);
            //exit as we can't analyze pyproject.toml - insufficient version information
            return;
        }

        final List<Toml> projectsLocks = result.getTables("package");
        if (projectsLocks == null) {
            return;
        }
        projectsLocks.forEach((project) -> {
            final String name = project.getString("name");
            final String version = project.getString("version");

            LOGGER.debug(String.format("package, version: %s %s", name, version));

            final Dependency d = new Dependency(dependency.getActualFile(), true);
            d.setName(name);
            d.setVersion(version);

            try {
                final PackageURL purl = PackageURLBuilder.aPackageURL()
                        .withType("pypi")
                        .withName(name)
                        .withVersion(version)
                        .build();
                d.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
            } catch (MalformedPackageURLException ex) {
                LOGGER.debug("Unable to build package url for pypi", ex);
                d.addSoftwareIdentifier(new GenericIdentifier("pypi:" + name + "@" + version, Confidence.HIGH));
            }

            d.setPackagePath(String.format("%s:%s", name, version));
            d.setEcosystem(PythonDistributionAnalyzer.DEPENDENCY_ECOSYSTEM);
            final String filePath = String.format("%s:%s/%s", dependency.getFilePath(), name, version);
            d.setFilePath(filePath);
            d.setSha1sum(Checksum.getSHA1Checksum(filePath));
            d.setSha256sum(Checksum.getSHA256Checksum(filePath));
            d.setMd5sum(Checksum.getMD5Checksum(filePath));
            d.addEvidence(EvidenceType.PRODUCT, POETRY_LOCK, "product", name, Confidence.HIGHEST);
            d.addEvidence(EvidenceType.VERSION, POETRY_LOCK, "version", version, Confidence.HIGHEST);
            d.addEvidence(EvidenceType.VENDOR, POETRY_LOCK, "vendor", name, Confidence.HIGHEST);
            engine.addDependency(d);
        });
    }

    private Optional<Toml> parseDependencyFile(Dependency dependency) {
        try {
            final Toml toml = new Toml().read(dependency.getActualFile());
            return Optional.of(toml);
        } catch (RuntimeException e) {
            final Optional<String> unparsableFileErrorMessage = Optional.ofNullable(e.getCause())
                    .filter(c -> c instanceof IllegalStateException)
                    .map(Throwable::getMessage)
                    .filter(PoetryAnalyzer::isInvalidKeyErrorMessage);

            if (unparsableFileErrorMessage.isPresent()) {
                final String message = String.format("Invalid toml file, cannot parse '%s'", dependency.getActualFile());
                LOGGER.debug(message, e);
                return Optional.empty();
            }

            throw e;
        }
    }

    private static boolean isInvalidKeyErrorMessage(String m) {
        return m.startsWith("Invalid key");
    }

    private void ensureLock(File parent) throws AnalysisException {
        final File lock = new File(parent, POETRY_LOCK);
        final File requirements = new File(parent, "requirements.txt");
        final boolean found = lock.isFile() || requirements.isFile();
        //do not throw an error if the pyproject.toml is in the node_modules (#5464).
        if (!found && !parent.toString().contains("node_modules")) {
            throw new AnalysisException("Python `pyproject.toml` found and there "
                    + "is not a `poetry.lock` or `requirements.txt` - analysis will be incomplete");
        }
    }
}
