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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.central.CentralSearch;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for the CentralAnalyzer.
 */
class CentralAnalyzerTest extends BaseTest {

    private static final String SHA1_SUM = "my-sha1-sum";
    final CentralSearch centralSearch = mock(CentralSearch.class);
    final Dependency dependency = mock(Dependency.class);

    @Test
    @SuppressWarnings("PMD.NonStaticInitializer")
    void testFetchMavenArtifactsWithoutException() throws IOException, TooManyRequestsException {
            CentralAnalyzer instance = new CentralAnalyzer();
            instance.setCentralSearch(centralSearch);
            when(dependency.getSha1sum()).thenReturn(SHA1_SUM);
            when(centralSearch.searchSha1(SHA1_SUM)).thenReturn(Collections.emptyList());

            final List<MavenArtifact> actualMavenArtifacts = instance.fetchMavenArtifacts(dependency);

            assertTrue(actualMavenArtifacts.isEmpty());
    }

    @Test
    @SuppressWarnings("PMD.NonStaticInitializer")
    void testFetchMavenArtifactsRethrowsFileNotFoundException() throws Exception {
        CentralAnalyzer instance = new CentralAnalyzer();
        instance.setCentralSearch(centralSearch);
        when(dependency.getSha1sum()).thenReturn(SHA1_SUM);
        when(centralSearch.searchSha1(SHA1_SUM)).thenThrow(FileNotFoundException.class);
        assertThrows(FileNotFoundException.class, () ->
            instance.fetchMavenArtifacts(dependency));
    }

    @Test
    @SuppressWarnings("PMD.NonStaticInitializer")
    void testFetchMavenArtifactsAlwaysThrowsIOException() throws Exception {
        getSettings().setInt(Settings.KEYS.ANALYZER_CENTRAL_RETRY_COUNT, 1);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_CENTRAL_USE_CACHE, false);
        CentralAnalyzer instance = new CentralAnalyzer();
        instance.initialize(getSettings());
        instance.setCentralSearch(centralSearch);
        when(dependency.getSha1sum()).thenReturn(SHA1_SUM);
        when(centralSearch.searchSha1(SHA1_SUM)).thenThrow(IOException.class);
        assertThrows(IOException.class, () ->
            instance.fetchMavenArtifacts(dependency));
    }
}
