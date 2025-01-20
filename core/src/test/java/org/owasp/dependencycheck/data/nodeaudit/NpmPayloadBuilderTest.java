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
package org.owasp.dependencycheck.data.nodeaudit;

import java.io.InputStream;

import org.junit.Assert;
import org.junit.Test;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonReader;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;

import org.owasp.dependencycheck.BaseTest;

public class NpmPayloadBuilderTest {

    @Test
    public void testSanitizer() {
        JsonObjectBuilder builder = Json.createObjectBuilder()
                .add("name", "my app")
                .add("version", "1.0.0")
                .add("random", "random")
                .add("lockfileVersion", 1)
                .add("requires", true)
                .add("dependencies",
                        Json.createObjectBuilder()
                                .add("abbrev",
                                        Json.createObjectBuilder()
                                                .add("version", "1.1.1")
                                                .add("resolved", "https://registry.npmjs.org/abbrev/-/abbrev-1.1.1.tgz")
                                                .add("integrity", "sha512-nne9/IiQ/hzIhY6pdDnbBtz7DjPTKrY00P/zvPSm5pOFkl6xuGrGnXn/VtTNNfNtAfZ9/1RtehkszU9qcTii0Q==")
                                                .add("dev", true)
                                )
                                .add("node_modules/jest-resolve",
                                        Json.createObjectBuilder()
                                                .add("dev", true)
                                                .add("optional", true)
                                                .add("peer", true))
                );

        JsonObject packageJson = builder.build();
        final MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        JsonObject sanitized = NpmPayloadBuilder.build(packageJson, dependencyMap, false);

        Assert.assertTrue(sanitized.containsKey("name"));
        Assert.assertTrue(sanitized.containsKey("version"));
        Assert.assertTrue(sanitized.containsKey("dependencies"));
        Assert.assertTrue(sanitized.containsKey("requires"));

        JsonObject dependencies = sanitized.getJsonObject("dependencies");
        Assert.assertTrue(dependencies.containsKey("node_modules/jest-resolve"));

        JsonObject requires = sanitized.getJsonObject("requires");
        Assert.assertTrue(requires.containsKey("abbrev"));
        Assert.assertEquals("^1.1.1", requires.getString("abbrev"));
        Assert.assertEquals("*", requires.getString("node_modules/jest-resolve"));

        Assert.assertFalse(sanitized.containsKey("lockfileVersion"));
        Assert.assertFalse(sanitized.containsKey("random"));
    }


    @Test
    public void testSkippedDependencies() {
        JsonObjectBuilder builder = Json.createObjectBuilder()
                .add("name", "my app")
                .add("version", "1.0.0")
                .add("random", "random")
                .add("lockfileVersion", 1)
                .add("requires", true)
                .add("dependencies",
                        Json.createObjectBuilder()
                                .add("abbrev",
                                        Json.createObjectBuilder()
                                                .add("version", "1.1.1")
                                                .add("resolved", "https://registry.npmjs.org/abbrev/-/abbrev-1.1.1.tgz")
                                                .add("integrity", "sha512-nne9/IiQ/hzIhY6pdDnbBtz7DjPTKrY00P/zvPSm5pOFkl6xuGrGnXn/VtTNNfNtAfZ9/1RtehkszU9qcTii0Q==")
                                                .add("dev", true)
                                )
                                .add("react-dom",
                                        Json.createObjectBuilder()
                                                .add("version", "npm:@hot-loader/react-dom")
                                )
                                .add("fake_submodule",
                                        Json.createObjectBuilder()
                                                .add("version", "file:fake_submodule")
                                )
                );

        JsonObject packageJson = builder.build();
        final MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        JsonObject sanitized = NpmPayloadBuilder.build(packageJson, dependencyMap, false);

        Assert.assertTrue(sanitized.containsKey("name"));
        Assert.assertTrue(sanitized.containsKey("version"));
        Assert.assertTrue(sanitized.containsKey("dependencies"));
        Assert.assertTrue(sanitized.containsKey("requires"));

        JsonObject requires = sanitized.getJsonObject("requires");
        Assert.assertTrue(requires.containsKey("abbrev"));
        Assert.assertEquals("^1.1.1", requires.getString("abbrev"));

        //local and alias need to be skipped
        Assert.assertFalse(requires.containsKey("react-dom"));
        Assert.assertFalse(requires.containsKey("fake_submodule"));

        Assert.assertFalse(sanitized.containsKey("lockfileVersion"));
        Assert.assertFalse(sanitized.containsKey("random"));
    }

    @Test
    public void testSanitizePackage() {
        InputStream in = BaseTest.getResourceAsStream(this, "nodeaudit/package-lock.json");
        final MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        try (JsonReader jsonReader = Json.createReader(in)) {
            JsonObject packageJson = jsonReader.readObject();
            JsonObject sanitized = NpmPayloadBuilder.build(packageJson, dependencyMap, false);

            Assert.assertTrue(sanitized.containsKey("name"));
            Assert.assertTrue(sanitized.containsKey("version"));
            Assert.assertTrue(sanitized.containsKey("dependencies"));
            Assert.assertTrue(sanitized.containsKey("requires"));

            JsonObject requires = sanitized.getJsonObject("requires");
            Assert.assertTrue(requires.containsKey("bcrypt-nodejs"));
            Assert.assertEquals("^0.0.3", requires.getString("bcrypt-nodejs"));

            Assert.assertFalse(sanitized.containsKey("lockfileVersion"));
            Assert.assertFalse(sanitized.containsKey("random"));
        }
    }

    @Test
    public void testPayloadWithLockAndPackage() {
        InputStream lock = BaseTest.getResourceAsStream(this, "nodeaudit/package-lock.json");
        InputStream json = BaseTest.getResourceAsStream(this, "nodeaudit/package.json");
        final MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        try (JsonReader jsonReader = Json.createReader(json); JsonReader lockReader = Json.createReader(lock)) {
            JsonObject packageJson = jsonReader.readObject();
            JsonObject lockJson =    lockReader.readObject();
            JsonObject sanitized = NpmPayloadBuilder.build(lockJson, packageJson, dependencyMap, false);

            Assert.assertTrue(sanitized.containsKey("name"));
            Assert.assertTrue(sanitized.containsKey("version"));
            Assert.assertTrue(sanitized.containsKey("dependencies"));
            Assert.assertTrue(sanitized.containsKey("requires"));

            JsonObject requires = sanitized.getJsonObject("requires");
            Assert.assertTrue(requires.containsKey("bcrypt-nodejs"));
            Assert.assertEquals("0.0.3", requires.getString("bcrypt-nodejs"));

            Assert.assertFalse(sanitized.containsKey("lockfileVersion"));
            Assert.assertFalse(sanitized.containsKey("random"));

            Assert.assertTrue(sanitized.containsKey("name"));
            Assert.assertTrue(sanitized.containsKey("version"));
            Assert.assertTrue(sanitized.containsKey("dependencies"));
            Assert.assertTrue(sanitized.containsKey("requires"));

            //local and alias need to be skipped
            Assert.assertFalse(requires.containsKey("react-dom"));
            Assert.assertFalse(requires.containsKey("fake_submodule"));
        }
    }
}
