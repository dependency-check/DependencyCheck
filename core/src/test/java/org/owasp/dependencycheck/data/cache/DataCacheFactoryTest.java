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

import org.apache.commons.jcs3.JCS;
import org.apache.commons.jcs3.access.CacheAccess;
import org.apache.commons.jcs3.auxiliary.AuxiliaryCache;
import org.apache.commons.jcs3.engine.ElementAttributes;
import org.apache.commons.jcs3.engine.behavior.ICacheElement;
import org.apache.commons.jcs3.engine.behavior.ICompositeCacheAttributes;
import org.apache.commons.jcs3.engine.behavior.IElementAttributes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the caches produced by {@link DataCacheFactory} against a real, disk-backed JCS instance configured from
 * the default {@code dependencycheck-cache.properties}, including the handling of caches written by earlier releases
 * whose elements were persisted as eternal.
 *
 * @author Jeremy Long
 */
class DataCacheFactoryTest extends BaseTest {

    private static final String TEST_REGION = "CENTRAL";
    private static final long CENTRAL_MAX_LIFE_SECONDS = Duration.ofDays(30).getSeconds();
    public static final List<MavenArtifact> TEST_VALUE = List.of(new MavenArtifact("org.example", "example", "1.0.0"));

    private DataCacheFactory factory;

    /**
     * Shuts JCS down, flushing all pending writes to disk, and re-initialises it from the default properties so that
     * subsequent reads are served from the on-disk cache rather than from in-memory purgatory.
     */
    @BeforeEach
    void initialize() {
        JCS.shutdown();
        factory = new DataCacheFactory(getSettings());
    }

    DataCacheFactory restartFactory() {
        awaitDiskWritesComplete();
        initialize();
        return factory;
    }

    /**
     * JCS disk writes are asynchronous, and its shutdown does not wait for a write that the event queue's thread pool
     * has already picked up, so a put immediately followed by a shutdown can be lost. Pending writes sit in the disk
     * cache's purgatory until written, so wait for that to drain before shutting down.
     */
    private static void awaitDiskWritesComplete() {
        final AuxiliaryCache<?, ?> disk = JCS.getInstance(TEST_REGION).getCacheControl().getAuxCacheList().get(0);
        final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (purgatorySize(disk) > 0) {
            assertTrue(System.nanoTime() < deadline, () -> "Timed out waiting for disk cache writes: " + disk.getStats());
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
        }
    }

    private static int purgatorySize(AuxiliaryCache<?, ?> disk) {
        return disk.getStatistics().getStatElements().stream()
                .filter(element -> "Purgatory Size".equals(element.getName()))
                .mapToInt(element -> (Integer) element.getData())
                .findFirst()
                .orElseThrow();
    }

    @AfterEach
    void removeCachedEntries() {
        JCS.<String, List<MavenArtifact>>getInstance(TEST_REGION).clear();
    }

    @Test
    void cachesAreCreatedOnDiskInTheDataDirectory() throws IOException {
        assertNotNull(factory.getCentralCache());
        assertNotNull(factory.getPomCache());
        assertNotNull(factory.getNodeAuditCache());

        final File cacheDirectory = new File(getSettings().getDataDirectory(), "cache");
        assertTrue(cacheDirectory.isDirectory());
        for (String region : List.of("CENTRAL", "POM", "NODEAUDIT")) {
            final File[] files = cacheDirectory.listFiles((dir, name) -> name.startsWith(region));
            assertNotNull(files);
            assertTrue(files.length > 0, "expected disk cache files for " + region);
        }
    }

    @Test
    void regionsInheritTheDefaultExpiryPolicy() {
        assertRegionPolicy("CENTRAL", Duration.ofDays(30));
        assertRegionPolicy("POM", Duration.ofDays(90));
        assertRegionPolicy("NODEAUDIT", Duration.ofDays(1));
    }

    @Test
    void entriesSurviveRestartWithNonEternalAttributes() {
        final DataCache<List<MavenArtifact>> cache = factory.getCentralCache();
        final String key = newKey();
        final long before = System.currentTimeMillis();
        cache.put(key, TEST_VALUE);

        final DataCache<List<MavenArtifact>> reopened = restartFactory().getCentralCache();

        final List<MavenArtifact> result = reopened.get(key);
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("org.example", result.get(0).getGroupId());
        assertEquals("example", result.get(0).getArtifactId());
        assertEquals("1.0.0", result.get(0).getVersion());

        final IElementAttributes attributes = elementAttributes(key);
        assertFalse(attributes.getIsEternal());
        assertEquals(CENTRAL_MAX_LIFE_SECONDS, attributes.getMaxLife());
        assertEquals(-1, attributes.getIdleTime());
        assertTrue(attributes.getCreateTime() >= before);
    }

    @Test
    void entriesOlderThanMaxLifeAreExpiredOnAccess() {
        final String key = newKey();
        final IElementAttributes attributes = JCS.getInstance(TEST_REGION).getDefaultElementAttributes();
        setCreateTime(attributes, daysAgo(31));
        factory.getCentralCache().put(key, TEST_VALUE, attributes);

        assertNull(restartFactory().getCentralCache().get(key));
        assertNull(JCS.getInstance(TEST_REGION).getCacheElement(key));
    }

    @Test
    void legacyEternalEntryWithinMaxLifeIsReturnedAndRepaired() {
        final String key = newKey();
        final long createTime = daysAgo(10);
        factory.getCentralCache().put(key, TEST_VALUE, legacyEternalAttributes(createTime));

        final DataCache<List<MavenArtifact>> cache = restartFactory().getCentralCache();
        final List<MavenArtifact> result = cache.get(key);
        assertNotNull(result);
        assertEquals("org.example", result.get(0).getGroupId());

        // immediately after the repair the entry is served from the disk cache's purgatory (pending write queue)
        final IElementAttributes pending = elementAttributes(key);
        assertFalse(pending.getIsEternal());
        assertEquals(createTime, pending.getCreateTime());
        assertNotNull(cache.get(key));

        // the repaired attributes must have been persisted to disk, retaining the original creation time
        final DataCache<List<MavenArtifact>> reopened = restartFactory().getCentralCache();
        final IElementAttributes repaired = elementAttributes(key);
        assertFalse(repaired.getIsEternal());
        assertEquals(CENTRAL_MAX_LIFE_SECONDS, repaired.getMaxLife());
        assertEquals(-1, repaired.getIdleTime());
        assertEquals(createTime, repaired.getCreateTime());
        assertNotNull(reopened.get(key));
    }

    @Test
    void legacyEternalEntryBeyondMaxLifeIsRemovedOnAccess() {
        final String key = newKey();
        factory.getCentralCache().put(key, TEST_VALUE, legacyEternalAttributes(daysAgo(31)));

        assertNull(restartFactory().getCentralCache().get(key));
        assertNull(JCS.getInstance(TEST_REGION).getCacheElement(key));

        assertNull(restartFactory().getCentralCache().get(key));
    }

    private String newKey() {
        return "DataCacheFactoryTest-" + UUID.randomUUID();
    }

    private IElementAttributes elementAttributes(String key) {
        final CacheAccess<String, List<MavenArtifact>> region = JCS.getInstance(TEST_REGION);
        final ICacheElement<String, List<MavenArtifact>> element = region.getCacheElement(key);
        assertNotNull(element, "expected element for " + key);
        return element.getElementAttributes();
    }

    /**
     * Element attributes as persisted by earlier releases, whose region configuration replaced the default element
     * attributes (eternal by default in JCS) and then only set MaxLife and the spool flags.
     */
    private static IElementAttributes legacyEternalAttributes(long createTime) {
        final ElementAttributes attributes = new ElementAttributes();
        attributes.setMaxLife(CENTRAL_MAX_LIFE_SECONDS);
        attributes.setIsSpool(true);
        attributes.setIsRemote(false);
        attributes.setIsLateral(false);
        assertTrue(attributes.getIsEternal(), "JCS default element attributes are expected to be eternal");
        setCreateTime(attributes, createTime);
        return attributes;
    }

    private static long daysAgo(int days) {
        return System.currentTimeMillis() - Duration.ofDays(days).toMillis();
    }

    /**
     * JCS only exposes a no-argument {@code setCreateTime()} that uses the current time.
     */
    private static void setCreateTime(IElementAttributes attributes, long createTime) {
        try {
            final Field field = ElementAttributes.class.getDeclaredField("createTime");
            field.setAccessible(true);
            field.setLong(attributes, createTime);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Unable to set createTime on " + attributes, e);
        }
    }

    private static void assertRegionPolicy(String region, Duration maxLife) {
        final CacheAccess<String, Object> access = JCS.getInstance(region);
        final IElementAttributes attributes = access.getDefaultElementAttributes();
        assertFalse(attributes.getIsEternal(), region + " elements must not be eternal");
        assertEquals(maxLife.getSeconds(), attributes.getMaxLife(), region + " MaxLife");
        assertEquals(-1, attributes.getIdleTime(), region + " IdleTime");
        assertTrue(attributes.getIsSpool(), region + " elements must spool to disk");
        assertFalse(attributes.getIsLateral(), region + " elements must not be lateral");
        assertFalse(attributes.getIsRemote(), region + " elements must not be remote");

        final ICompositeCacheAttributes cacheAttributes = access.getCacheAttributes();
        assertEquals(0, cacheAttributes.getMaxObjects(), region + " MaxObjects");
        assertEquals(ICompositeCacheAttributes.DiskUsagePattern.UPDATE, cacheAttributes.getDiskUsagePattern(), region + " DiskUsagePattern");
        assertTrue(cacheAttributes.isUseDisk(), region + " must use disk");
    }
}
