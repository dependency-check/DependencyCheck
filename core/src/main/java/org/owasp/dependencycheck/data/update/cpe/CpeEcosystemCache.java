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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.cpe;

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;

import org.owasp.dependencycheck.utils.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Jeremy Long
 */
public final class CpeEcosystemCache {

    /**
     * The keyword/ecosystem used when multiple ecosystems have been identified.
     */
    private static final String MULTIPLE_ECOSYSTEMS_IDENTIFIED = "MULTIPLE";
    /**
     * The cache of CPE to ecosystem mappings.
     */
    private static Map<Pair<String, String>, String> cache = new HashMap<>();
    /**
     * The map of ecosystem entries that have been updated.
     */
    private static Map<Pair<String, String>, String> changed = new HashMap<>();

    private CpeEcosystemCache() {
        //empty constructor for utility class
    }
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CpeEcosystemCache.class);

    //CSOFF: EmptyBlock
    /**
     * Returns the ecosystem for the given CPE (vendor, product). If the CPE has
     * a different ecosystem previously identified the ecosystem will be updated
     * to Multiple; otherwise, if an ecosystem is provided it will be cached for
     * future matching.
     *
     * @param vendor the vendor for the CPE
     * @param product the product for the CPE
     * @param identifiedEcosystem the ecosystem identified for a CVE.
     * @return the ecosystem
     */
    public static synchronized String getEcosystem(String vendor, String product, String identifiedEcosystem) {
        final Pair<String, String> key = new Pair<>(vendor, product);
        final String current = cache.get(key);
        String result = null;
        if (current == null) {
            if (!StringUtils.isBlank(identifiedEcosystem)) {
                cache.put(key, identifiedEcosystem);
                changed.put(key, identifiedEcosystem);
                result = identifiedEcosystem;
            }
        } else if (MULTIPLE_ECOSYSTEMS_IDENTIFIED.equals(current)) {
            //do nothing - result is already null
        } else if (current.equals(identifiedEcosystem) || identifiedEcosystem == null) {
            result = current;
        } else {
            cache.put(key, MULTIPLE_ECOSYSTEMS_IDENTIFIED);
            changed.put(key, MULTIPLE_ECOSYSTEMS_IDENTIFIED);
        }
        return result;
    }
    //CSON: EmptyBlock

    /**
     * Sets the ecosystem cache and resets the changed map.
     *
     * @param cache the new CPE to ecosystem mapping
     */
    public static synchronized void setCache(Map<Pair<String, String>, String> cache) {
        CpeEcosystemCache.cache = cache;
        CpeEcosystemCache.changed = new HashMap<>();
    }

    /**
     * Returns the map of changed CPE to ecosystem mappings.
     *
     * @return the map of changed CPE to ecosystem mappings
     */
    public static synchronized Map<Pair<String, String>, String> getChanged() {
        return CpeEcosystemCache.changed;
    }

    /**
     * Returns <code>true</code> if the ecosystem cache is empty; otherwise
     * <code>false</code>.
     *
     * @return <code>true</code> if the ecosystem cache is empty; otherwise
     * <code>false</code>
     */
    public static synchronized boolean isEmpty() {
        return CpeEcosystemCache.cache.isEmpty();
    }
}
