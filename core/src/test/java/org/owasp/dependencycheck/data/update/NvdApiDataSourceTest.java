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
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 *
 * @author Jeremy Long
 */
class NvdApiDataSourceTest {

    /**
     * Test of extractUrlData method, of class NvdApiDataSource.
     */
    @Test
    void testExtractUrlData() {
        String nvdDataFeedUrl = "https://internal.server/nist/nvdcve-{0}.json.gz";
        NvdApiDataSource instance = new NvdApiDataSource();
        String expectedUrl = "https://internal.server/nist/";
        String expectedPattern = "nvdcve-{0}.json.gz";
        NvdApiDataSource.UrlData result = instance.extractUrlData(nvdDataFeedUrl);

        nvdDataFeedUrl = "https://internal.server/nist/";
        expectedUrl = "https://internal.server/nist/";
        result = instance.extractUrlData(nvdDataFeedUrl);

        assertEquals(expectedUrl, result.getUrl());
        assertNull(result.getPattern());

        nvdDataFeedUrl = "https://internal.server/nist";
        expectedUrl = "https://internal.server/nist/";
        result = instance.extractUrlData(nvdDataFeedUrl);

        assertEquals(expectedUrl, result.getUrl());
        assertNull(result.getPattern());
    }

//    /**
//     * Test of getRemoteCacheProperties method, of class NvdApiDataSource.
//     */
//    @Test
//    public void testGetRemoteCacheProperties() throws Exception {
//        System.out.println("getRemoteCacheProperties");
//        String url = "";
//        NvdApiDataSource instance = new NvdApiDataSource();
//        Properties expResult = null;
//        Properties result = instance.getRemoteCacheProperties(url);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
}
