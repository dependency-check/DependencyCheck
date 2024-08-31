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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */

import org.apache.commons.lang3.StringUtils

String oldReport = new File(basedir, "old/target/dependency-check-report.xml").text
int count = StringUtils.countMatches(oldReport, "pkg:maven/org.slf4j/slf4j-api@1.7.30");
if (count == 0) {
    System.out.println("pkg:maven/org.slf4j/slf4j-api@1.7.30 was not identified and is a dependency of war-1.0.0-SNAPSHOT via lib-1.0.0-SNAPSHOT");
    return false;
}

String newReport = new File(basedir, "new/target/dependency-check-report.xml").text
count = StringUtils.countMatches(newReport, "pkg:maven/org.slf4j/slf4j-api@1.7.30");
if (count != 0) {
    System.out.println("pkg:maven/org.slf4j/slf4j-api@1.7.30 was identified but has been removed as a dependency in the new project to simulate mitigating vulnerabilities");
    return false;
}

return true;