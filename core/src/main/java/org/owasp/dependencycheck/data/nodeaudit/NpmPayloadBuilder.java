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

import org.owasp.dependencycheck.analyzer.NodePackageAnalyzer;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.stream.Collectors;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.collections4.MultiValuedMap;

/**
 * Class used to create the payload to submit to the NPM Audit API service.
 *
 * @author Steve Springett
 * @author Jeremy Long
 */
@ThreadSafe
public final class NpmPayloadBuilder {

    /**
     * Private constructor for utility class.
     */
    private NpmPayloadBuilder() {
        //empty
    }

    /**
     * Builds an npm audit API payload.
     *
     * @param lockJson the package-lock.json
     * @param packageJson the package.json
     * @param dependencyMap a collection of module/version pairs that is
     * populated while building the payload
     * @param skipDevDependencies whether devDependencies should be skipped
     * @return the npm audit API payload
     */
    public static JsonObject build(JsonObject lockJson, JsonObject packageJson,
            MultiValuedMap<String, String> dependencyMap, boolean skipDevDependencies) {
        final JsonObjectBuilder payloadBuilder = Json.createObjectBuilder();
        addProjectInfo(packageJson, payloadBuilder);

        // NPM Audit expects 'requires' to be an object containing key/value
        // pairs corresponding to the module name (key) and version (value).
        final JsonObjectBuilder requiresBuilder = Json.createObjectBuilder();

        if (packageJson.containsKey("dependencies")) {
            packageJson.getJsonObject("dependencies").entrySet()
                    .stream()
                    .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            Map.Entry::getValue,
                            (oldValue, newValue) -> newValue, TreeMap::new))
                    .forEach((key, value) -> {
                        if (NodePackageAnalyzer.shouldSkipDependency(key, ((JsonString) value).getString())) {
                            return;
                        }
                        requiresBuilder.add(key, value);
                        dependencyMap.put(key, value.toString());
                    });
        }

        if (!skipDevDependencies && packageJson.containsKey("devDependencies")) {
            packageJson.getJsonObject("devDependencies").entrySet()
                    .stream()
                    .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            Map.Entry::getValue,
                            (oldValue, newValue) -> newValue, TreeMap::new))
                    .forEach((key, value) -> {
                        if (NodePackageAnalyzer.shouldSkipDependency(key, ((JsonString) value).getString())) {
                            return;
                        }
                        requiresBuilder.add(key, value);
                        dependencyMap.put(key, value.toString());
                    });
        }

        payloadBuilder.add("requires", requiresBuilder.build());

        final JsonObjectBuilder dependenciesBuilder = Json.createObjectBuilder();
        final int lockJsonVersion = lockJson.containsKey("lockfileVersion") ? lockJson.getInt("lockfileVersion") : 1;
        JsonObject dependencies = lockJson.getJsonObject("dependencies");
        if (lockJsonVersion >= 2 && dependencies == null) {
            dependencies = lockJson.getJsonObject("packages");
        }

        if (dependencies != null) {
            dependencies.forEach((k, value) -> {
                String key = k;
                final int indexOfNodeModule = key.lastIndexOf(NodePackageAnalyzer.NODE_MODULES_DIRNAME + "/");
                if (indexOfNodeModule >= 0) {
                    key = key.substring(indexOfNodeModule + NodePackageAnalyzer.NODE_MODULES_DIRNAME.length() + 1);
                }

                JsonObject dep = ((JsonObject) value);

                //After Version 3, dependencies can't be taken directly from package-lock.json
                if (lockJsonVersion > 2 && dep.containsKey("dependencies") && dep.get("dependencies") instanceof JsonObject) {
                    final JsonObjectBuilder depBuilder = Json.createObjectBuilder(dep);
                    depBuilder.remove("dependencies");
                    depBuilder.add("requires", dep.get("dependencies"));
                    dep = depBuilder.build();
                }

                final String version = dep.getString("version", "");
                final boolean isDev = dep.getBoolean("dev", false);
                if (skipDevDependencies && isDev) {
                    return;
                }
                if (NodePackageAnalyzer.shouldSkipDependency(key, version)) {
                    return;
                }
                dependencyMap.put(key, version);
                dependenciesBuilder.add(key, buildDependencies(dep, dependencyMap));
            });
        }
        payloadBuilder.add("dependencies", dependenciesBuilder.build());

        addConstantElements(payloadBuilder);
        return payloadBuilder.build();
    }

    /**
     * Attempts to build the request data for NPM Audit API call. This may
     * produce a payload that will fail.
     *
     * @param packageJson a raw package-lock.json file
     * @param dependencyMap a collection of module/version pairs that is
     * @param skipDevDependencies whether devDependencies should be skipped
     * populated while building the payload
     * @return the JSON payload for NPN Audit
     */
    public static JsonObject build(JsonObject packageJson, MultiValuedMap<String, String> dependencyMap,
            final boolean skipDevDependencies) {
        final JsonObjectBuilder payloadBuilder = Json.createObjectBuilder();
        addProjectInfo(packageJson, payloadBuilder);

        // NPM Audit expects 'requires' to be an object containing key/value
        // pairs corresponding to the module name (key) and version (value).
        final JsonObjectBuilder requiresBuilder = Json.createObjectBuilder();
        final JsonObjectBuilder dependenciesBuilder = Json.createObjectBuilder();

        final JsonObject dependencies = packageJson.getJsonObject("dependencies");
        if (dependencies != null) {
            dependencies.forEach((name, value) -> {
                final String version;
                if (value.getValueType() == JsonValue.ValueType.OBJECT) {
                    final JsonObject dep = ((JsonObject) value);
                    version = Optional.ofNullable(dep.getJsonString("version"))
                            .map(JsonString::getString)
                            .orElse(null);

                    final boolean isDev = dep.getBoolean("dev", false);
                    if (skipDevDependencies && isDev) {
                        return;
                    }
                    if (NodePackageAnalyzer.shouldSkipDependency(name, version)) {
                        return;
                    }
                    dependencyMap.put(name, version);
                    dependenciesBuilder.add(name, buildDependencies(dep, dependencyMap));
                } else {
                    //TODO I think the following is dead code and no real "dependencies"
                    //     section in a lock file will look like this
                    final String tmp = value.toString();
                    if (tmp.startsWith("\"")) {
                        version = tmp.substring(1, tmp.length() - 1);
                    } else {
                        version = tmp;
                    }
                }
                requiresBuilder.add(name, Objects.isNull(version) ? "*" : "^" + version);
            });
        }
        payloadBuilder.add("requires", requiresBuilder.build());

        payloadBuilder.add("dependencies", dependenciesBuilder.build());

        addConstantElements(payloadBuilder);
        return payloadBuilder.build();
    }

    /**
     * Adds the project name and version to the npm audit API payload.
     *
     * @param packageJson a reference to the package-lock.json
     * @param payloadBuilder a reference to the npm audit API payload builder
     */
    private static void addProjectInfo(JsonObject packageJson, final JsonObjectBuilder payloadBuilder) {
        final String projectName = packageJson.getString("name", "");
        final String projectVersion = packageJson.getString("version", "");
        if (!projectName.isEmpty()) {
            payloadBuilder.add("name", projectName);
        }
        if (!projectVersion.isEmpty()) {
            payloadBuilder.add("version", projectVersion);
        }
    }

    /**
     * Adds the constant data elements to the npm audit API payload.
     *
     * @param payloadBuilder a reference to the npm audit API payload builder
     */
    private static void addConstantElements(final JsonObjectBuilder payloadBuilder) {
        payloadBuilder.add("install", Json.createArrayBuilder().build());
        payloadBuilder.add("remove", Json.createArrayBuilder().build());
        payloadBuilder.add("metadata", Json.createObjectBuilder()
                .add("npm_version", "6.9.0")
                .add("node_version", "v10.5.0")
                .add("platform", "linux")
        );
    }

    /**
     * Recursively builds the dependency structure - copying only the needed
     * items from the package-lock.json into the npm audit API payload.
     *
     * @param dep the parent dependency
     * @param dependencyMap the collection of child dependencies
     * @return the dependencies structure needed for the npm audit API payload
     */
    private static JsonObject buildDependencies(JsonObject dep, MultiValuedMap<String, String> dependencyMap) {
        final JsonObjectBuilder depBuilder = Json.createObjectBuilder();
        Optional.ofNullable(dep.getJsonString("version"))
                .map(JsonString::getString)
                .ifPresent(version -> depBuilder.add("version", version));

        //not installed package (like, dependency of an optional dependency) doesn't contains integrity
        if (dep.containsKey("integrity")) {
            depBuilder.add("integrity", dep.getString("integrity"));
        }
        if (dep.containsKey("requires")) {
            final JsonObjectBuilder requiresBuilder = Json.createObjectBuilder();
            dep.getJsonObject("requires").forEach((key, value) -> {
                if (NodePackageAnalyzer.shouldSkipDependency(key, ((JsonString) value).getString())) {
                    return;
                }

                requiresBuilder.add(key, value);
            });
            depBuilder.add("requires", requiresBuilder.build());
        }
        if (dep.containsKey("dependencies")) {
            final JsonObjectBuilder dependeciesBuilder = Json.createObjectBuilder();
            dep.getJsonObject("dependencies").forEach((key, value) -> {
                if (value.getValueType() == JsonValue.ValueType.OBJECT) {
                    final JsonObject currentDep = (JsonObject) value;
                    final String v = currentDep.getString("version");
                    dependencyMap.put(key, v);
                    dependeciesBuilder.add(key, buildDependencies(currentDep, dependencyMap));
                } else {
                    final String tmp = value.toString();
                    final String v;
                    if (tmp.startsWith("\"")) {
                        v = tmp.substring(1, tmp.length() - 1);
                    } else {
                        v = tmp;
                    }
                    dependencyMap.put(key, v);
                    dependeciesBuilder.add(key, v);
                }
            });
            depBuilder.add("dependencies", dependeciesBuilder.build());
        }
        return depBuilder.build();
    }
}
