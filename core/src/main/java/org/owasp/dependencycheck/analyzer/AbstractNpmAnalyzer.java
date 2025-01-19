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
 * Copyright (c) 2017 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURL.StandardTypes;
import com.github.packageurl.PackageURLBuilder;
import org.semver4j.Semver;
import org.semver4j.SemverException;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.data.nodeaudit.NodeAuditSearch;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import javax.annotation.concurrent.ThreadSafe;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.JsonValue.ValueType;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.analyzer.exception.UnexpectedAnalysisException;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Checksum;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

/**
 * An abstract NPM analyzer that contains common methods for concrete
 * implementations.
 *
 * @author Steve Springett
 */
@ThreadSafe
public abstract class AbstractNpmAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractNpmAnalyzer.class);

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String NPM_DEPENDENCY_ECOSYSTEM = Ecosystem.NODEJS;
    /**
     * The file name to scan.
     */
    private static final String PACKAGE_JSON = "package.json";

    /**
     * The Node Audit Searcher.
     */
    private NodeAuditSearch searcher;

    /**
     * Determines if the file can be analyzed by the analyzer.
     *
     * @param pathname the path to the file
     * @return true if the file can be analyzed by the given analyzer; otherwise
     * false
     */
    @Override
    public boolean accept(File pathname) {
        boolean accept = super.accept(pathname);
        if (accept) {
            try {
                accept = shouldProcess(pathname);
            } catch (AnalysisException ex) {
                throw new UnexpectedAnalysisException(ex.getMessage(), ex.getCause());
            }
        }
        return accept;
    }

    /**
     * Determines if the path contains "/node_modules/" or "/bower_components/"
     * (i.e. it is a child module). This analyzer does not scan child modules.
     *
     * @param pathname the path to test
     * @return <code>true</code> if the path does not contain "/node_modules/"
     * or "/bower_components/"
     * @throws AnalysisException thrown if the canonical path cannot be obtained
     * from the given file
     */
    public static boolean shouldProcess(File pathname) throws AnalysisException {
        try {
            // Do not scan the node_modules (or bower_components) directory
            final String canonicalPath = pathname.getCanonicalPath();
            if (canonicalPath.contains(File.separator + "node_modules" + File.separator)
                    || canonicalPath.contains(File.separator + "bower_components" + File.separator)) {
                LOGGER.debug("Skipping analysis of node/bower module: {}", canonicalPath);
                return false;
            }
        } catch (IOException ex) {
            throw new AnalysisException("Unable to process dependency", ex);
        }
        return true;
    }

    /**
     * Construct a dependency object.
     *
     * @param dependency the parent dependency
     * @param name the name of the dependency to create
     * @param version the version of the dependency to create
     * @param scope the scope of the dependency being created
     * @return the generated dependency
     */
    protected Dependency createDependency(Dependency dependency, String name, String version, String scope) {
        final Dependency nodeModule = new Dependency(new File(dependency.getActualFile() + "?" + name), true);
        nodeModule.setEcosystem(NPM_DEPENDENCY_ECOSYSTEM);
        //this is virtual - the sha1 is purely for the hyperlink in the final html report
        nodeModule.setSha1sum(Checksum.getSHA1Checksum(String.format("%s:%s", name, version)));
        nodeModule.setSha256sum(Checksum.getSHA256Checksum(String.format("%s:%s", name, version)));
        nodeModule.setMd5sum(Checksum.getMD5Checksum(String.format("%s:%s", name, version)));
        nodeModule.addEvidence(EvidenceType.PRODUCT, "package.json", "name", name, Confidence.HIGHEST);
        nodeModule.addEvidence(EvidenceType.VENDOR, "package.json", "name", name, Confidence.HIGH);
        if (!StringUtils.isBlank(version)) {
            nodeModule.addEvidence(EvidenceType.VERSION, "package.json", "version", version, Confidence.HIGHEST);
            nodeModule.setVersion(version);
        }
        if (dependency.getName() != null) {
            nodeModule.addProjectReference(dependency.getName() + ": " + scope);
        } else {
            nodeModule.addProjectReference(dependency.getDisplayFileName() + ": " + scope);
        }
        nodeModule.setName(name);

        //TODO  - we can likely create a valid CPE as a low confidence guess using cpe:2.3:a:[name]_project:[name]:[version]
        //(and add a targetSw of npm/node)
        Identifier id;
        try {
            final PackageURL purl = PackageURLBuilder.aPackageURL().withType(StandardTypes.NPM)
                    .withName(name).withVersion(version).build();
            id = new PurlIdentifier(purl, Confidence.HIGHEST);
        } catch (MalformedPackageURLException ex) {
            LOGGER.debug("Unable to generate Purl - using a generic identifier instead " + ex.getMessage());
            id = new GenericIdentifier(String.format("npm:%s@%s", dependency.getName(), version), Confidence.HIGHEST);
        }
        nodeModule.addSoftwareIdentifier(id);
        return nodeModule;
    }

    /**
     * Processes a part of package.json (as defined by JsonArray) and update the
     * specified dependency with relevant info.
     *
     * @param engine the dependency-check engine
     * @param dependency the Dependency to update
     * @param jsonArray the jsonArray to parse
     * @param depType the dependency type
     */
    protected void processPackage(Engine engine, Dependency dependency, JsonArray jsonArray, String depType) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        jsonArray.getValuesAs(JsonString.class).forEach((str) -> builder.add(str.toString(), ""));
        final JsonObject jsonObject = builder.build();
        processPackage(engine, dependency, jsonObject, depType);
    }

    /**
     * Processes a part of package.json (as defined by JsonObject) and update
     * the specified dependency with relevant info.
     *
     * @param engine the dependency-check engine
     * @param dependency the Dependency to update
     * @param jsonObject the jsonObject to parse
     * @param depType the dependency type
     */
    protected void processPackage(Engine engine, Dependency dependency, JsonObject jsonObject, String depType) {
        for (int i = 0; i < jsonObject.size(); i++) {
            jsonObject.forEach((name, value) -> {
                String version = "";
                if (value != null && value.getValueType() == ValueType.STRING) {
                    version = ((JsonString) value).getString();
                }
                final Dependency existing = findDependency(engine, name, version);
                if (existing == null) {
                    final Dependency nodeModule = createDependency(dependency, name, version, depType);
                    engine.addDependency(nodeModule);
                } else {
                    existing.addProjectReference(dependency.getName() + ": " + depType);
                }
            });
        }
    }

    /**
     * Adds information to an evidence collection from the node json
     * configuration.
     *
     * @param dep the dependency to add the evidence
     * @param t the type of evidence to add
     * @param json information from node.js
     * @return the actual string set into evidence
     * @param key the key to obtain the data from the json information
     */
    private static String addToEvidence(Dependency dep, EvidenceType t, JsonObject json, String key) {
        String evidenceStr = null;
        if (json.containsKey(key)) {
            final JsonValue value = json.get(key);
            if (value instanceof JsonString) {
                evidenceStr = ((JsonString) value).getString();
                dep.addEvidence(t, PACKAGE_JSON, key, evidenceStr, Confidence.HIGHEST);
            } else if (value instanceof JsonObject) {
                final JsonObject jsonObject = (JsonObject) value;
                for (final Map.Entry<String, JsonValue> entry : jsonObject.entrySet()) {
                    final String property = entry.getKey();
                    final JsonValue subValue = entry.getValue();
                    if (subValue instanceof JsonString) {
                        evidenceStr = ((JsonString) subValue).getString();
                        dep.addEvidence(t, PACKAGE_JSON,
                                String.format("%s.%s", key, property),
                                evidenceStr,
                                Confidence.HIGHEST);
                    } else {
                        LOGGER.warn("JSON sub-value not string as expected: {}", subValue);
                    }
                }
            } else if (value instanceof JsonArray) {
                final JsonArray jsonArray = (JsonArray) value;
                jsonArray.forEach(entry -> {
                    if (entry instanceof JsonObject) {
                        ((JsonObject) entry).keySet().forEach(item -> {
                            final JsonValue v = ((JsonObject) entry).get(item);
                            if (v instanceof JsonString) {
                                final String eStr = ((JsonString) v).getString();
                                dep.addEvidence(t, PACKAGE_JSON,
                                        String.format("%s.%s", key, item),
                                        eStr,
                                        Confidence.HIGHEST);
                            }
                        });
                    }
                });
            } else {
                LOGGER.warn("JSON value not string or JSON object as expected: {}", value);
            }
        }
        return evidenceStr;
    }

    /**
     * Locates the dependency from the list of dependencies that have been
     * scanned by the engine.
     *
     * @param engine the dependency-check engine
     * @param name the name of the dependency to find
     * @param version the version of the dependency to find
     * @return the identified dependency; otherwise null
     */
    protected Dependency findDependency(Engine engine, String name, String version) {
        for (Dependency d : engine.getDependencies()) {
            if (NPM_DEPENDENCY_ECOSYSTEM.equals(d.getEcosystem()) && name.equals(d.getName()) && version != null && d.getVersion() != null) {
                final String dependencyVersion = d.getVersion();
                if (DependencyBundlingAnalyzer.npmVersionsMatch(version, dependencyVersion)) {
                    return d;
                }
            }
        }
        return null;
    }

    /**
     * Collects evidence from the given JSON for the associated dependency.
     *
     * @param json the JSON that contains the evidence to collect
     * @param dependency the dependency to add the evidence too
     */
    public void gatherEvidence(final JsonObject json, Dependency dependency) {
        String displayName = null;
        if (json.containsKey("name")) {
            final Object value = json.get("name");
            if (value instanceof JsonString) {
                final String valueString = ((JsonString) value).getString();
                displayName = valueString;
                dependency.setName(valueString);
                dependency.setPackagePath(valueString);
                dependency.addEvidence(EvidenceType.PRODUCT, PACKAGE_JSON, "name", valueString, Confidence.HIGHEST);
                dependency.addEvidence(EvidenceType.VENDOR, PACKAGE_JSON, "name", valueString, Confidence.HIGHEST);
                dependency.addEvidence(EvidenceType.VENDOR, PACKAGE_JSON, "name", valueString + "_project", Confidence.HIGHEST);
            } else {
                LOGGER.warn("JSON value not string as expected: {}", value);
            }
        }
        //TODO - if we start doing CPE analysis on node - we need to exclude description as it creates too many FP
        final String desc = addToEvidence(dependency, EvidenceType.VENDOR, json, "description");
        dependency.setDescription(desc);
        String vendor = addToEvidence(dependency, EvidenceType.VENDOR, json, "author");
        if (vendor == null) {
            vendor = addToEvidence(dependency, EvidenceType.VENDOR, json, "maintainers");
        } else {
            addToEvidence(dependency, EvidenceType.VENDOR, json, "maintainers");
        }
        addToEvidence(dependency, EvidenceType.VENDOR, json, "homepage");
        addToEvidence(dependency, EvidenceType.VENDOR, json, "bugs");

        final String version = addToEvidence(dependency, EvidenceType.VERSION, json, "version");
        if (version != null) {
            displayName = String.format("%s:%s", displayName, version);
            dependency.setVersion(version);
            dependency.setPackagePath(displayName);
            Identifier id;
            try {
                final PackageURL purl = PackageURLBuilder.aPackageURL()
                        .withType(StandardTypes.NPM).withName(dependency.getName()).withVersion(version).build();
                id = new PurlIdentifier(purl, Confidence.HIGHEST);
            } catch (MalformedPackageURLException ex) {
                LOGGER.debug("Unable to generate Purl - using a generic identifier instead " + ex.getMessage());
                id = new GenericIdentifier(String.format("npm:%s:%s", dependency.getName(), version), Confidence.HIGHEST);
            }
            dependency.addSoftwareIdentifier(id);
        }
        if (displayName != null) {
            dependency.setDisplayFileName(displayName);
            dependency.setPackagePath(displayName);
        } else {
            LOGGER.warn("Unable to determine package name or version for {}", dependency.getActualFilePath());
            if (vendor != null && !vendor.isEmpty()) {
                dependency.setDisplayFileName(String.format("%s package.json", vendor));
            }
        }
        // Adds the license if defined in package.json
        if (json.containsKey("license")) {
            final Object value = json.get("license");
            if (value instanceof JsonString) {
                dependency.setLicense(json.getString("license"));
            } else if (value instanceof JsonArray) {
                final JsonArray array = (JsonArray) value;
                final StringBuilder sb = new StringBuilder();
                boolean addComma = false;
                for (int x = 0; x < array.size(); x++) {
                    if (!array.isNull(x)) {
                        if (addComma) {
                            sb.append(", ");
                        } else {
                            addComma = true;
                        }
                        if (ValueType.STRING == array.get(x).getValueType()) {
                            sb.append(array.getString(x));
                        } else {
                            final JsonObject lo = array.getJsonObject(x);
                            if (lo.containsKey("type") && !lo.isNull("type")
                                    && lo.containsKey("url") && !lo.isNull("url")) {
                                final String license = String.format("%s (%s)", lo.getString("type"), lo.getString("url"));
                                sb.append(license);
                            } else if (lo.containsKey("type") && !lo.isNull("type")) {
                                sb.append(lo.getString("type"));
                            } else if (lo.containsKey("url") && !lo.isNull("url")) {
                                sb.append(lo.getString("url"));
                            }
                        }
                    }
                }
                dependency.setLicense(sb.toString());
            } else {
                dependency.setLicense(json.getJsonObject("license").getString("type"));
            }
        }
    }

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException if there's an error during initialization
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        if (!isEnabled() || !getFilesMatched()) {
            this.setEnabled(false);
            return;
        }
        if (searcher == null) {
            LOGGER.debug("Initializing {}", getName());
            try {
                searcher = new NodeAuditSearch(getSettings());
            } catch (MalformedURLException ex) {
                setEnabled(false);
                throw new InitializationException("The configured URL to NPM Audit API is malformed", ex);
            }
            try {
                final Settings settings = engine.getSettings();
                final boolean nodeEnabled = settings.getBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED);
                if (!nodeEnabled) {
                    LOGGER.warn("The Node Package Analyzer has been disabled; the resulting report will only "
                            + "contain the known vulnerable dependency - not a bill of materials for the node project.");
                }
            } catch (InvalidSettingException ex) {
                throw new InitializationException("Unable to read configuration settings", ex);
            }
        }
    }

    /**
     * Processes the advisories creating the appropriate dependency objects and
     * adding the resulting vulnerabilities.
     *
     * @param advisories a collection of advisories from npm
     * @param engine a reference to the analysis engine
     * @param dependency a reference to the package-lock.json dependency
     * @param dependencyMap a collection of module/version pairs obtained from
     * the package-lock file - used in case the advisories do not include a
     * version number
     * @throws CpeValidationException thrown when a CPE cannot be created
     */
    protected void processResults(final List<Advisory> advisories, Engine engine,
            Dependency dependency, MultiValuedMap<String, String> dependencyMap)
            throws CpeValidationException {
        for (Advisory advisory : advisories) {
            //Create a new vulnerability out of the advisory returned by nsp.
            final Vulnerability vuln = new Vulnerability();
            vuln.setDescription(advisory.getOverview());
            vuln.setName(String.valueOf(advisory.getGhsaId()));
            vuln.setUnscoredSeverity(advisory.getSeverity());
            vuln.setCvssV3(advisory.getCvssV3());
            vuln.setSource(Vulnerability.Source.NPM);
            for (String cwe : advisory.getCwes()) {
                vuln.addCwe(cwe);
            }
            if (advisory.getReferences() != null) {
                final String[] references = advisory.getReferences().split("\\n");
                for (String reference : references) {
                    if (reference.length() > 3) {
                        String url = reference.substring(2);
                        try {
                            new URL(url);
                        } catch (MalformedURLException ignored) {
                            // reference is not a format-valid URL, so null it to make the reference be used as plaintext
                            url = null;
                        }
                        vuln.addReference("NPM Advisory reference: ", url == null ? reference : url, url);
                    }
                }
            }

            //Create a single vulnerable software object - these do not use CPEs unlike the NVD.
            final VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();
            builder.part(Part.APPLICATION).product(advisory.getModuleName().replace(" ", "_"))
                    .version(advisory.getVulnerableVersions().replace(" ", ""));
            final VulnerableSoftware vs = builder.build();
            vuln.addVulnerableSoftware(vs);

            String version = advisory.getVersion();
            if (version == null && dependencyMap.containsKey(advisory.getModuleName())) {
                version = determineVersionFromMap(advisory.getVulnerableVersions(), dependencyMap.get(advisory.getModuleName()));
            }
            final Dependency existing = findDependency(engine, advisory.getModuleName(), version);
            if (existing == null) {
                final Dependency nodeModule = createDependency(dependency, advisory.getModuleName(), version, "transitive");
                nodeModule.addVulnerability(vuln);
                engine.addDependency(nodeModule);
            } else {
                replaceOrAddVulnerability(existing, vuln);
            }
        }
    }

    /**
     * Evaluates if the vulnerability is already present; if it is the
     * vulnerability is not added.
     *
     * @param dependency a reference to the dependency being analyzed
     * @param vuln the vulnerability to add
     */
    protected void replaceOrAddVulnerability(Dependency dependency, Vulnerability vuln) {
        final boolean found = vuln.getSource() == Vulnerability.Source.NPM
                && dependency.getVulnerabilities().stream().anyMatch(existing -> {
                    return existing.getReferences().stream().anyMatch(ref -> {
                        return ref.getName() != null
                                && ref.getName().equals("https://nodesecurity.io/advisories/" + vuln.getName());
                    });
                });
        if (!found) {
            dependency.addVulnerability(vuln);
        }
    }

    /**
     * Returns the node audit search utility.
     *
     * @return the node audit search utility
     */
    protected NodeAuditSearch getSearcher() {
        return searcher;
    }

    /**
     * Give an NPM version range and a collection of versions, this method
     * attempts to select a specific version from the collection that is in the
     * range.
     *
     * @param versionRange the version range to evaluate
     * @param availableVersions the collection of possible versions to select
     * @return the selected range from the versionRange
     */
    public static String determineVersionFromMap(String versionRange, Collection<String> availableVersions) {
        if (availableVersions.size() == 1) {
            return availableVersions.iterator().next();
        }
        for (String v : availableVersions) {
            try {
                final Semver version = new Semver(v);
                if (version.satisfies(versionRange)) {
                    return v;
                }
            } catch (SemverException ex) {
                LOGGER.debug("invalid semver: " + v);
            }
        }
        return availableVersions.iterator().next();
    }
}
