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
 * Copyright (c) 2026 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.golang;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a single vulnerability reported by
 * <code>govulncheck -json</code>. Each result joins the OSV advisory record
 * (identified by its <code>GO-YYYY-NNNN</code> id) with the most precise
 * finding emitted for it (the module, version, and - when the vulnerable symbol
 * is reachable - the calling package and function).
 *
 * @author Srinivas Chippagiri
 */
public class GovulncheckResult {

    /**
     * The Go vulnerability database id (e.g. <code>GO-2022-0969</code>).
     */
    private final String id;
    /**
     * The aliases for the vulnerability (e.g. CVE and GHSA ids); used to
     * de-duplicate against vulnerabilities reported by other data sources.
     */
    private final List<String> aliases;
    /**
     * A short summary of the vulnerability.
     */
    private final String summary;
    /**
     * The detailed description of the vulnerability.
     */
    private final String details;
    /**
     * The reference URLs for the vulnerability.
     */
    private final List<String> references;
    /**
     * The vulnerable module path (e.g. <code>golang.org/x/net</code>).
     */
    private final String moduleName;
    /**
     * The version of the vulnerable module in use.
     */
    private final String moduleVersion;
    /**
     * The first version in which the vulnerability is fixed; may be null.
     */
    private final String fixedVersion;
    /**
     * The vulnerable package that is imported; may be null when only the module
     * is known.
     */
    private final String packageName;
    /**
     * The reachable vulnerable symbol; may be null when the vulnerability is not
     * known to be called.
     */
    private final String symbol;

    //CSOFF: ParameterNumber
    /**
     * Constructs a new govulncheck result.
     *
     * @param id the Go vulnerability database id
     * @param aliases the CVE/GHSA aliases
     * @param summary a short summary
     * @param details the detailed description
     * @param references the reference URLs
     * @param moduleName the vulnerable module path
     * @param moduleVersion the version of the module in use
     * @param fixedVersion the first fixed version (may be null)
     * @param packageName the vulnerable package that is imported (may be null)
     * @param symbol the reachable vulnerable symbol (may be null)
     */
    public GovulncheckResult(String id, List<String> aliases, String summary, String details, List<String> references,
            String moduleName, String moduleVersion, String fixedVersion, String packageName, String symbol) {
        this.id = id;
        this.aliases = aliases == null ? new ArrayList<>() : aliases;
        this.summary = summary;
        this.details = details;
        this.references = references == null ? new ArrayList<>() : references;
        this.moduleName = moduleName;
        this.moduleVersion = moduleVersion;
        this.fixedVersion = fixedVersion;
        this.packageName = packageName;
        this.symbol = symbol;
    }
    //CSON: ParameterNumber

    /**
     * Returns the Go vulnerability database id.
     *
     * @return the id
     */
    public String getId() {
        return id;
    }

    /**
     * Returns the CVE/GHSA aliases.
     *
     * @return the aliases
     */
    public List<String> getAliases() {
        return aliases;
    }

    /**
     * Returns the short summary.
     *
     * @return the summary
     */
    public String getSummary() {
        return summary;
    }

    /**
     * Returns the detailed description.
     *
     * @return the details
     */
    public String getDetails() {
        return details;
    }

    /**
     * Returns the reference URLs.
     *
     * @return the references
     */
    public List<String> getReferences() {
        return references;
    }

    /**
     * Returns the vulnerable module path.
     *
     * @return the module path
     */
    public String getModuleName() {
        return moduleName;
    }

    /**
     * Returns the version of the vulnerable module in use.
     *
     * @return the module version
     */
    public String getModuleVersion() {
        return moduleVersion;
    }

    /**
     * Returns the first version in which the vulnerability is fixed.
     *
     * @return the fixed version; may be null
     */
    public String getFixedVersion() {
        return fixedVersion;
    }

    /**
     * Returns the vulnerable package that is imported.
     *
     * @return the package name; may be null
     */
    public String getPackageName() {
        return packageName;
    }

    /**
     * Returns the reachable vulnerable symbol.
     *
     * @return the symbol; may be null
     */
    public String getSymbol() {
        return symbol;
    }

    /**
     * Indicates whether the vulnerable symbol is reachable (called) from the
     * scanned code. When {@code false} the module is present but govulncheck did
     * not observe a call into the vulnerable code.
     *
     * @return <code>true</code> if a vulnerable symbol is called
     */
    public boolean isCalled() {
        return symbol != null && !symbol.isEmpty();
    }
}
