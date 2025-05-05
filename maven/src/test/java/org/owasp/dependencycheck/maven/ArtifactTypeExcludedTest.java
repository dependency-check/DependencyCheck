/*
 * This file is part of dependency-check-maven.
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
package org.owasp.dependencycheck.maven;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 * @author Jeremy Long
 */
class ArtifactTypeExcludedTest {

    /**
     * Test of passes method, of class ArtifactTypeExcluded.
     */
    @Test
    void testPasses() {
        String artifactType = null;
        ArtifactTypeExcluded instance = new ArtifactTypeExcluded(null);
        boolean expResult = false;
        boolean result = instance.passes(artifactType);
        assertEquals(expResult, result);

        artifactType = "pom";
        instance = new ArtifactTypeExcluded(null);
        expResult = false;
        result = instance.passes(artifactType);
        assertEquals(expResult, result);
        
        artifactType = null;
        instance = new ArtifactTypeExcluded("jar");
        expResult = false;
        result = instance.passes(artifactType);
        assertEquals(expResult, result);
        
        artifactType = "pom";
        instance = new ArtifactTypeExcluded("");
        expResult = false;
        result = instance.passes(artifactType);
        assertEquals(expResult, result);
        
        artifactType = "pom";
        instance = new ArtifactTypeExcluded("jar");
        expResult = false;
        result = instance.passes(artifactType);
        assertEquals(expResult, result);
        
        artifactType = "pom";
        instance = new ArtifactTypeExcluded("pom");
        expResult = true;
        result = instance.passes(artifactType);
        assertEquals(expResult, result);
        
        artifactType = "pom";
        instance = new ArtifactTypeExcluded(".*");
        expResult = true;
        result = instance.passes(artifactType);
        assertEquals(expResult, result);
    }

}
