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
 * Copyright (c) 2020 OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;

import io.github.jeremylong.openvulnerability.client.nvd.Config;

import java.util.Objects;
import java.util.stream.Collectors;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;

import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import io.github.jeremylong.openvulnerability.client.nvd.LangString;
import io.github.jeremylong.openvulnerability.client.nvd.Node;
import java.util.List;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;

/**
 *
 * Utility for processing {@linkplain DefCveItem} in order to extract key values
 * like textual description and ecosystem type.
 *
 * @author skjolber
 */
public class CveItemOperator {

    /**
     * The filter for 2.3 CPEs in the CVEs - we don't import unless we get a
     * match.
     */
    private final String cpeStartsWithFilter;

    /**
     * Constructs a new CVE Item Operator utility.
     *
     * @param cpeStartsWithFilter the filter to use for CPE entries
     */
    public CveItemOperator(String cpeStartsWithFilter) {
        this.cpeStartsWithFilter = cpeStartsWithFilter;
    }

    /**
     * Extracts the english description from the CVE object.
     *
     * @param cve the CVE data
     * @return the English descriptions from the CVE object
     */
    public String extractDescription(DefCveItem cve) {
        return cve.getCve().getDescriptions().stream().filter((desc)
                -> "en".equals(desc.getLang())).map(LangString::getValue).collect(Collectors.joining(" "));
    }

    //CSOFF: MissingSwitchDefault
    /**
     * Attempts to determine the ecosystem based on the vendor, product and
     * targetSw.
     *
     * @param baseEcosystem the base ecosystem
     * @param vendor the vendor
     * @param product the product
     * @param targetSw the target software
     * @return the ecosystem if one is identified
     */
    private String extractEcosystem(String baseEcosystem, String vendor, String product, String targetSw) {
        //TODO the following was added to reduce the need for the slow UPDATE_ECOSYSTEM2 query
        // the following should be analyzed to determine if an ecosystem should be returned.
        // Note that these all have 'bindings' in the description of a vulnerability in more than
        // one case these were related to language bindings; as such the list need to be reviewed and refined.
        if (("mysql".equals(vendor) && "mysql".equals(product))
                || ("postgresql".equals(vendor) && "postgresql".equals(product))
                || ("picketlink".equals(vendor) && "picketlink".equals(product))
                || ("libxl_project".equals(vendor) && "libxl".equals(product))
                || ("ocaml".equals(vendor) && "postgresql-ocaml".equals(product))
                || ("curses_project".equals(vendor) && "curses".equals(product))
                || ("dalekjs".equals(vendor) && "dalekjs".equals(product))
                || ("microsoft".equals(vendor) && "internet_explorer".equals(product))
                || ("jenkins".equals(vendor) && "ssh_credentials".equals(product))
                || ("kubernetes".equals(vendor) && "kubernetes".equals(product))
                || ("gnome".equals(vendor) && "nautilus-python".equals(product))
                || ("apache".equals(vendor) && "qpid_proton".equals(product))
                || ("mysql-ocaml".equals(vendor) && "mysql-ocaml".equals(product))
                || ("google".equals(vendor) && "chrome".equals(product))
                || ("canonical".equals(vendor) && "ltsp_display_manager".equals(product))
                || ("gnome".equals(vendor) && "vala".equals(product))
                || ("apple".equals(vendor) && "safari".equals(product))
                || ("mapbox".equals(vendor) && "npm-test-sqlite3-trunk".equals(product))
                || ("apple".equals(vendor) && "webkit".equals(product))
                || ("mozilla".equals(vendor) && "firefox".equals(product))
                || ("apache".equals(vendor) && "thrift".equals(product))
                || ("apache".equals(vendor) && "qpid".equals(product))
                || ("mozilla".equals(vendor) && "thunderbird".equals(product))
                || ("mozilla".equals(vendor) && "firefox_esr".equals(product))
                || ("redhat".equals(vendor) && "jboss_amq_clients_2".equals(product))
                || ("node-opencv_project".equals(vendor) && "node-opencv".equals(product))
                || ("mozilla".equals(vendor) && "seamonkey".equals(product))
                || ("mozilla".equals(vendor) && "thunderbird_esr".equals(product))
                || ("mnet_soft_factory".equals(vendor) && "nodemanager_professional".equals(product))
                || ("mozilla".equals(vendor) && "mozilla_suite".equals(product))
                || ("theforeman".equals(vendor) && "hammer_cli".equals(product))
                || ("ibm".equals(vendor) && "websphere_application_server".equals(product))
                || ("sap".equals(vendor) && "hana_extend_application_services".equals(product))
                || ("apache".equals(vendor) && "zookeeper".equals(product))) {
            return null;
        }

        if ("ibm".equals(vendor)
                && "java".equals(product)) {
            return Ecosystem.NATIVE;
        }

        if ("oracle".equals(vendor)
                && "vm".equals(product)) {
            return Ecosystem.NATIVE;
        }
        switch (targetSw) {
            case "asp.net"://.net
            case "c#"://.net
            case ".net"://.net
            case "dotnetnuke"://.net
                return Ecosystem.DOTNET;
            case "android"://android
            case "java"://java
                return Ecosystem.JAVA;
            case "c/c++"://c++
            case "borland_c++"://c++
            case "visual_c++"://c++
            case "gnu_c++"://c++
            case "linux_kernel"://native
            case "linux"://native
            case "unix"://native
            case "suse_linux"://native
            case "redhat_enterprise_linux"://native
            case "debian"://native
                return Ecosystem.NATIVE;
            case "coldfusion"://coldfusion
                return Ecosystem.COLDFUSION;
            case "ios"://ios
            case "iphone"://ios
            case "ipad"://ios
            case "iphone_os"://ios
                return Ecosystem.IOS;
            case "jquery"://javascript
                return Ecosystem.JAVASCRIPT;
            case "node.js"://node.js
            case "nodejs"://node.js
                return Ecosystem.NODEJS;
            case "perl"://perl
                return Ecosystem.PERL;
            case "joomla!"://php
            case "joomla"://php
            case "mybb"://php
            case "simplesamlphp"://php
            case "craft_cms"://php
            case "moodle"://php
            case "phpcms"://php
            case "buddypress"://php
            case "typo3"://php
            case "php"://php
            case "wordpress"://php
            case "drupal"://php
            case "mediawiki"://php
            case "symfony"://php
            case "openpne"://php
            case "vbulletin3"://php
            case "vbulletin4"://php
                return Ecosystem.PHP;
            case "python"://python
                return Ecosystem.PYTHON;
            case "ruby"://ruby
                return Ecosystem.RUBY;
        }
        return baseEcosystem;
    }
    //CSON: MissingSwitchDefault

    /**
     * Attempts to determine the ecosystem based on the vendor, product and
     * targetSw.
     *
     * @param baseEcosystem the base ecosystem
     * @param parsedCpe the CPE identifier
     * @return the ecosystem if one is identified
     */
    public String extractEcosystem(String baseEcosystem, VulnerableSoftware parsedCpe) {
        return extractEcosystem(baseEcosystem, parsedCpe.getVendor(), parsedCpe.getProduct(), parsedCpe.getTargetSw());
    }

    /**
     * Determines if the CVE entry is rejected.
     *
     * @param description the CVE description
     * @return <code>true</code> if the CVE was rejected; otherwise
     * <code>false</code>
     */
    public boolean isRejected(String description) {
        return description.startsWith("** REJECT **") || description.startsWith("DO NOT USE THIS CANDIDATE NUMBER");
    }

    /**
     * Tests the CVE's CPE entries against the starts with filter. In general
     * this limits the CVEs imported to just application level vulnerabilities.
     *
     * @param cve the CVE entry to examine
     * @return <code>true</code> if the CVE affects CPEs identified by the
     * configured CPE Starts with filter
     */
    boolean testCveCpeStartWithFilter(final DefCveItem cve) {
        if (cve.getCve().getConfigurations() != null) {
            //cycle through to see if this is a CPE we care about (use the CPE filters
            return cve.getCve().getConfigurations().stream()
                    .map(Config::getNodes)
                    .flatMap(List::stream)
                    .filter(Objects::nonNull)
                    .map(Node::getCpeMatch)
                    .filter(Objects::nonNull)
                    .flatMap(List::stream)
                    .filter(cpe -> cpe != null && cpe.getCriteria() != null)
                    .anyMatch(cpe -> cpe.getCriteria().startsWith(cpeStartsWithFilter));
        }
        return false;
    }
}
