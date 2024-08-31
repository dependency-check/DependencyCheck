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

// Check to see if jackson-dataformat-xml-2.4.5.jar was identified.
//TODO change this to xpath and check for CVE-2018-11307
String log = new File(basedir, "target/dependency-check-report.xml").text
int count = StringUtils.countMatches(log, "<name>CVE-2018-11307</name>");
if (count == 0){
    System.out.println(String.format("jackson-dataformat-xml (CVE-2018-11307) was not identified", count));
    return false;
}
return true;
