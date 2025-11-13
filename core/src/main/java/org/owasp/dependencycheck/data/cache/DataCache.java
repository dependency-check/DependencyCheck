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

import org.apache.commons.jcs3.access.CacheAccess;

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
     * Creates a new generic JCS wrapper.
     *
     * @param cache a reference to the underlying cache implementation.
     */
    DataCache(CacheAccess<String, T> cache) {
        this.cache = cache;
    }

    /**
     * Gets an object from the cache.
     *
     * @param key the key for the cached object
     * @return the cached object
     */
    public T get(String key) {
        return cache.get(key);
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
}
