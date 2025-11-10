/*
 * This file is part of dependency-check-utils.
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
 * Copyright (c) 2025 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for SuppressionSyncAnalyzer, particularly the git diff parsing logic.
 */
class SuppressionSyncAnalyzerTest {

    /**
     * Test parsing a simple deletion from a git diff.
     */
    @Test
    void testParseDeletedSuppressions_SimpleDeletion() throws Exception {
        String gitDiff = "diff --git a/generatedSuppressions.xml b/generatedSuppressions.xml\n" +
                "index abc123..def456 100644\n" +
                "--- a/generatedSuppressions.xml\n" +
                "+++ b/generatedSuppressions.xml\n" +
                "@@ -1,10 +1,5 @@\n" +
                "-    <suppress base=\"true\">\n" +
                "-        <notes><![CDATA[\n" +
                "-        FP per issue #1234\n" +
                "-        ]]></notes>\n" +
                "-        <packageUrl regex=\"true\">^pkg:maven/com\\.example/test@.*$</packageUrl>\n" +
                "-        <cpe>cpe:/a:example:test</cpe>\n" +
                "-    </suppress>\n" +
                "     <suppress base=\"true\">\n" +
                "         <notes><![CDATA[\n" +
                "         Another suppression\n";

        List<?> result = parseDeletedSuppressions(gitDiff);
        
        System.out.println("Found " + result.size() + " deletions");
        for (Object o : result) {
            System.out.println("  - " + o);
        }
        
        assertEquals(1, result.size(), "Should find exactly one deleted suppression");
        
        Object suppression = result.get(0);
        String packageUrl = (String) getField(suppression, "packageUrl");
        System.out.println("PackageURL: " + packageUrl);
        assertEquals("^pkg:maven/com\\.example/test@.*$", packageUrl);
        
        @SuppressWarnings("unchecked")
        java.util.Set<String> cpes = (java.util.Set<String>) getField(suppression, "cpes");
        System.out.println("CPEs: " + cpes);
        assertTrue(cpes.contains("cpe:/a:example:test"));
    }

    /**
     * Test parsing a deletion where the opening tag is context (no '-' prefix).
     */
    @Test
    void testParseDeletedSuppressions_ContextOpeningTag() throws Exception {
        String gitDiff = "@@ -720,10 +720,5 @@\n" +
                " <suppress base=\"true\">\n" +
                "-    <notes><![CDATA[\n" +
                "-    FP per issue #5857; akka-projection-grpc is not grpc itself\n" +
                "-    ]]></notes>\n" +
                "-    <packageUrl regex=\"true\">^pkg:maven/com\\.lightbend\\.akka/akka-projection-grpc.*$</packageUrl>\n" +
                "-    <cpe>cpe:/a:grpc:grpc</cpe>\n" +
                "-</suppress>\n" +
                "-<suppress base=\"true\">\n";

        List<?> result = parseDeletedSuppressions(gitDiff);
        
        System.out.println("Found " + result.size() + " deletions with context opening tag");
        assertEquals(1, result.size(), "Should find one deleted suppression with context opening tag");
        
        Object suppression = result.get(0);
        String packageUrl = (String) getField(suppression, "packageUrl");
        System.out.println("PackageURL: " + packageUrl);
        assertEquals("^pkg:maven/com\\.lightbend\\.akka/akka-projection-grpc.*$", packageUrl);
        
        @SuppressWarnings("unchecked")
        java.util.Set<String> cpes = (java.util.Set<String>) getField(suppression, "cpes");
        assertTrue(cpes.contains("cpe:/a:grpc:grpc"));
    }

    /**
     * Test parsing multiple deletions in one diff.
     */
    @Test
    void testParseDeletedSuppressions_MultipleDeletions() throws Exception {
        String gitDiff = "diff --git a/generatedSuppressions.xml b/generatedSuppressions.xml\n" +
                "@@ -100,20 +100,5 @@\n" +
                "-    <suppress base=\"true\">\n" +
                "-        <notes><![CDATA[FP per issue #4851]]></notes>\n" +
                "-        <packageUrl regex=\"true\">^pkg:maven/com\\.graphql-java/graphql-java-extended-scalars@.*$</packageUrl>\n" +
                "-        <cpe>cpe:/a:graphql-java_project:graphql-java</cpe>\n" +
                "-    </suppress>\n" +
                "-    <suppress base=\"true\">\n" +
                "-        <notes><![CDATA[FP per issue #4852]]></notes>\n" +
                "-        <packageUrl regex=\"true\">^pkg:maven/com\\.graphql-java-kickstart/graphql-java-kickstart@.*$</packageUrl>\n" +
                "-        <cpe>cpe:/a:graphql-java_project:graphql-java</cpe>\n" +
                "-    </suppress>\n" +
                "+    <suppress base=\"true\">\n" +
                "+        <notes><![CDATA[Consolidated suppression for graphql-java]]></notes>\n" +
                "+        <packageUrl regex=\"true\">^pkg:(?!maven/com\\.graphql-java/graphql-java@).*$</packageUrl>\n" +
                "+        <cpe>cpe:/a:graphql-java:graphql-java</cpe>\n" +
                "+    </suppress>\n";

        List<?> result = parseDeletedSuppressions(gitDiff);
        
        System.out.println("Found " + result.size() + " deletions");
        assertEquals(2, result.size(), "Should find two deleted suppressions");
        
        // Verify first deletion
        Object first = result.get(0);
        String firstUrl = (String) getField(first, "packageUrl");
        System.out.println("First packageURL: " + firstUrl);
        assertEquals("^pkg:maven/com\\.graphql-java/graphql-java-extended-scalars@.*$", firstUrl);
        
        // Verify second deletion
        Object second = result.get(1);
        String secondUrl = (String) getField(second, "packageUrl");
        System.out.println("Second packageURL: " + secondUrl);
        assertEquals("^pkg:maven/com\\.graphql-java-kickstart/graphql-java-kickstart@.*$", secondUrl);
    }

    // Helper methods to access private fields/methods via reflection
    
    @SuppressWarnings("unchecked")
    private List<?> parseDeletedSuppressions(String diff) throws Exception {
        Class<?> clazz = Class.forName("org.owasp.dependencycheck.utils.SuppressionSyncAnalyzer");
        Method method = clazz.getDeclaredMethod("parseDeletedSuppressions", String.class);
        method.setAccessible(true);
        return (List<?>) method.invoke(null, diff);
    }
    
    private Object getField(Object obj, String fieldName) throws Exception {
        var field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }
}
