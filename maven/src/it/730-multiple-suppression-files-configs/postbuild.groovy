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
 * Copyright (c) 2017 The OWASP Foundation. All Rights Reserved.
 */

import org.apache.commons.lang3.StringUtils

// Check that suppression worked.
String log = new File(basedir, "build.log").text
int count = StringUtils.countMatches(log, "CVE-2016-5696");
if (count > 0) {
    System.out.println(String.format("CVE-2016-5696 (android-json-0.0.20131108.vaadin1.jar) was identified and should be suppressed"));
    return false;
}
count = StringUtils.countMatches(log, "CVE-2016-7051");
if (count > 0) {
    System.out.println(String.format("CVE-2016-7051 (jackson-module-jaxb-annotations-2.4.5.jar) was identified and should be suppressed"));
    return false;
}
