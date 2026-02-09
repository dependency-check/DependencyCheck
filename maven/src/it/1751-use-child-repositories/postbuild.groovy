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

import groovy.xml.XmlSlurper

String report = new File(basedir, "target/dependency-check-report.xml").text;

def analysis = new XmlSlurper().parseText(report);
def databindDep = analysis.dependencies.'*'.find { node -> node.fileName.text() == 'jackson-databind-2.4.3.jar' };
def references = databindDep.projectReferences.projectReference;

int refCount = references.size();
if (refCount != 2) {
    System.out.println("Failed to find both project references");
    return false;
}
if (!references.find { node -> node.text() == '1751-child-one:compile' }) {
    System.out.println("Should find reference from 1751-child-one to jackson-databind");
    return false
}
if (!references.find { node -> node.text() == '1751-child-two:compile' }) {
    System.out.println("Should find reference from 1751-child-two to jackson-databind");
    return false
}
if (!databindDep.vulnerabilities.vulnerability.name.find { node -> node.text() == 'CVE-2018-7489' }) {
    System.out.println("Failed to identify vulnerability CVE-2018-7489 in Jackson");
    return false;
}

return true;