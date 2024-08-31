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

import java.nio.charset.StandardCharsets
import java.nio.file.Files;

String report = new File(basedir, "target/dependency-check-report.xml").text
int count = StringUtils.countMatches(report, "org.owasp.test.aggregate:fourth:1.0.0-SNAPSHOT");
if (count == 0) {
    System.out.println(String.format("fourth-1.0.0-SNAPSHOT was not identified"));
    return false;
}
count = StringUtils.countMatches(report, "pkg:maven/org.apache.james/apache-mime4j-core@0.7.2");
if (count == 0) {
    System.out.println("org.apache.james:apache-mime4j-core:0.7.2 was not identified and is a dependency of fourth-1.0.0-SNAPSHOT");
    return false;
}
count = StringUtils.countMatches(report, "HelloWorld.js");
if (count == 0) {
    System.out.println("HelloWorld.js was not included via ScanSet and is found in `second/srt/test`");
    return false;
}

return true;