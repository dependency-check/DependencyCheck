/*
 * This file is part of dependency-check-ant.
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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.taskdefs;

/**
 * Class : {@link RetirejsFilter} Responsibility : Models a Retire JS file
 content filter nested XML element where the simple content is its regex.
 *
 * @author Jeremy Long
 */
// Poorly named class that doesn't match RetireJsFilter,
// see https://github.com/dependency-check/DependencyCheck/pull/8355#discussion_r2901538854
public class RetirejsFilter {

    /**
     * The regular expression for the Retire JS Content Filter.
     */
    private String regex;

    /**
     * Get the regex of regex.
     *
     * @return the regex of regex
     */
    public String getRegex() {
        return regex;
    }

    /**
     * Set the regex of regex.
     *
     * @param regex new regex of regex
     */
    public void setRegex(String regex) {
        this.regex = regex;
    }

}
