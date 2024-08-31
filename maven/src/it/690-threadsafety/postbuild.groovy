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
 
String log = new File(basedir, "build.log").text
int count = StringUtils.countMatches(log, "Download Started for NVD CVE - 2020");
if (count > 1){
    System.out.println(String.format("NVD CVE was downloaded %s times, should be 0 or 1 times", count));
    return false;
}
return true;