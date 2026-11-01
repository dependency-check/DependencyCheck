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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cache;

import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.jcs3.access.CacheAccess;
import org.apache.commons.jcs3.engine.behavior.ICacheElement;
import org.apache.commons.jcs3.engine.behavior.IElementAttributes;

/**
 * A generic wrapper for the Java Caching System (JCS).
 *
 * @param <T> the object type that will be cached
 *
 * @author Jeremy Long
 */
public class DataCache<T> {

    /**
     * A reference to the JCS cache.
     */
    private final CacheAccess<String, T> cache;
    /**
     * The intended policy configured for the cache region; for reconciling to existing elements with legacy configuration
     */
    private final IElementAttributes regionAttributes;

    /**
     * Creates a new generic JCS wrapper.
     *
     * @param cache a reference to the underlying cache implementation.
     */
    DataCache(CacheAccess<String, T> cache) {
        this.cache = cache;
        this.regionAttributes = cache.getDefaultElementAttributes();
    }

    /**
     * Gets an object from the cache.
     *
     * @param key the key for the cached object
     * @return the cached object
     */
    public T get(String key) {
        final ICacheElement<String, T> element = cache.getCacheElement(key);
        if (element == null) {
            return null;
        }
        if (!regionAttributes.getIsEternal() && element.getElementAttributes().getIsEternal()) {
            return repairToNonEternal(element);
        }
        return element.getVal();
    }

    /**
     * Releases configured before 13.0.1 accidentally configured the cache regions such that elements were persisted
     * to disk as eternal, so JCS would never expire them according to intended policy.
     * This resets the element's attributes to the region's current expiry policy while retaining its
     * original creation time: an element that is still within its lifetime is kept (and re-persisted with corrected
     * attributes so that JCS manages its expiry from here on) rather than being discarded and re-fetched, while an
     * element that has outlived the policy is removed.
     *
     * @param element the eternal element retrieved from the cache
     * @return the cached object if it is still within its lifetime; otherwise {@code null}
     */
    private T repairToNonEternal(ICacheElement<String, T> element) {
        final IElementAttributes attributes = element.getElementAttributes();
        attributes.setIsEternal(regionAttributes.getIsEternal());
        attributes.setMaxLife(regionAttributes.getMaxLife());
        attributes.setIdleTime(regionAttributes.getIdleTime());
        if (cache.getCacheControl().isExpired(element)) {
            cache.remove(element.getKey());
            return null;
        }
        cache.put(element.getKey(), element.getVal(), attributes);
        return element.getVal();
    }

    /**
     * Puts an object into the cache.
     *
     * @param key the key for the cached object
     * @param content the object to put into the cache
     */
    public void put(String key, T content) {
        cache.put(key, content);
    }

    @VisibleForTesting
    void put(String key, T content, IElementAttributes attributes) {
        cache.put(key, content, attributes);
    }
}
