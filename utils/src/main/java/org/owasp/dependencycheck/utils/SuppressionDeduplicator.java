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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Interactive utility to deduplicate suppressions between the base suppression file
 * and the generated suppressions file.
 *
 * This tool identifies duplicates and allows the user to interactively decide which
 * suppression to keep (base or generated) or skip the decision.
 */
public class SuppressionDeduplicator {

    private static final String GENERATED_SUPPRESSIONS_URL =
            "https://raw.githubusercontent.com/dependency-check/DependencyCheck/refs/heads/generatedSuppressions/generatedSuppressions.xml";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java SuppressionDeduplicator <path-to-base-suppression.xml> [--non-interactive]");
            System.err.println("  --non-interactive: Remove all duplicates from base without prompting");
            System.exit(1);
        }

        String basePath = args[0];
        boolean interactive = true;
        
        if (args.length > 1 && "--non-interactive".equals(args[1])) {
            interactive = false;
        }

        System.out.println("=== DependencyCheck Suppression Deduplicator ===\n");
        System.out.println("Base suppression file: " + basePath);
        System.out.println("Generated suppressions URL: " + GENERATED_SUPPRESSIONS_URL);
        System.out.println();

        // Parse both files
        System.out.println("Parsing suppression files...");
        Document baseDoc = parseXmlFile(basePath);
        Document generatedDoc = parseXmlFromUrl(GENERATED_SUPPRESSIONS_URL);

        List<Suppression> baseSuppressions = extractSuppressions(baseDoc, "base");
        List<Suppression> generatedSuppressions = extractSuppressions(generatedDoc, "generated");

        System.out.println("Found " + baseSuppressions.size() + " suppressions in base file");
        System.out.println("Found " + generatedSuppressions.size() + " suppressions in generated file\n");

        // Find duplicates
        System.out.println("Identifying duplicates...");
        List<DuplicatePair> duplicates = findDuplicates(baseSuppressions, generatedSuppressions);
        
        if (duplicates.isEmpty()) {
            System.out.println("No duplicates found! Files are already synchronized.");
            return;
        }

        System.out.println("Found " + duplicates.size() + " potential duplicates\n");

        // Process duplicates
        Set<Suppression> toRemoveFromBase = new HashSet<>();
        
        if (interactive) {
            toRemoveFromBase = processInteractive(duplicates);
        } else {
            System.out.println("Non-interactive mode: Removing all duplicates from base file");
            toRemoveFromBase = duplicates.stream()
                    .map(d -> d.base)
                    .collect(Collectors.toSet());
        }

        if (toRemoveFromBase.isEmpty()) {
            System.out.println("\nNo suppressions selected for removal. Exiting without changes.");
            return;
        }

        // Remove selected suppressions from base file using line-based approach
        System.out.println("\nRemoving " + toRemoveFromBase.size() + " suppressions from base file...");
        
        String backupPath = basePath + ".backup";
        System.out.println("Creating backup: " + backupPath);
        Files.copy(Paths.get(basePath), Paths.get(backupPath),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        System.out.println("Writing updated file: " + basePath);
        removeSuppressionsLineByLine(basePath, toRemoveFromBase);

        System.out.println("\n=== Complete ===");
        System.out.println("Removed " + toRemoveFromBase.size() + " duplicate suppressions from base file");
        System.out.println("Backup saved to: " + backupPath);
    }

    private static Set<Suppression> processInteractive(List<DuplicatePair> duplicates) throws IOException {
        Set<Suppression> toRemoveFromBase = new HashSet<>();
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        for (int i = 0; i < duplicates.size(); i++) {
            DuplicatePair dup = duplicates.get(i);
            
            System.out.println("=".repeat(80));
            System.out.println("Duplicate " + (i + 1) + " of " + duplicates.size());
            System.out.println("=".repeat(80));
            
            System.out.println("\n[BASE FILE]");
            System.out.println(dup.base.toString());
            
            System.out.println("\n[GENERATED FILE]");
            System.out.println(dup.generated.toString());
            
            System.out.println("\nMatch reason: " + dup.matchReason);
            System.out.println("\nWhat would you like to do?");
            System.out.println("  (R) Remove from base file (keep generated)");
            System.out.println("  (K) Keep in base file (both will exist)");
            System.out.println("  (S) Skip this decision");
            System.out.println("  (Q) Quit without saving");
            System.out.println("  (A) Remove all remaining duplicates from base");
            System.out.print("\nChoice [R/K/S/Q/A]: ");
            
            String choice = reader.readLine().trim().toUpperCase();
            
            switch (choice) {
                case "R":
                    toRemoveFromBase.add(dup.base);
                    System.out.println("✓ Will remove from base\n");
                    break;
                case "K":
                    System.out.println("✓ Will keep in base\n");
                    break;
                case "S":
                    System.out.println("⊘ Skipped\n");
                    break;
                case "Q":
                    System.out.println("\nQuitting without changes.");
                    System.exit(0);
                    break;
                case "A":
                    // Add current and all remaining
                    toRemoveFromBase.add(dup.base);
                    for (int j = i + 1; j < duplicates.size(); j++) {
                        toRemoveFromBase.add(duplicates.get(j).base);
                    }
                    System.out.println("✓ Will remove all remaining duplicates from base\n");
                    return toRemoveFromBase;
                default:
                    System.out.println("Invalid choice, skipping.\n");
            }
        }
        
        return toRemoveFromBase;
    }

    private static List<DuplicatePair> findDuplicates(List<Suppression> baseList, List<Suppression> generatedList) {
        List<DuplicatePair> duplicates = new ArrayList<>();
        
        for (Suppression base : baseList) {
            for (Suppression generated : generatedList) {
                String matchReason = findMatchReason(base, generated);
                if (matchReason != null) {
                    duplicates.add(new DuplicatePair(base, generated, matchReason));
                    break; // Only match once per base suppression
                }
            }
        }
        
        return duplicates;
    }

    private static String findMatchReason(Suppression s1, Suppression s2) {
        // For exact matching (ignoring notes), all fields must match
        // Check packageUrl (key field)
        if (!Objects.equals(s1.packageUrl, s2.packageUrl)) {
            return null;
        }
        
        // Check gav (key field)
        if (!Objects.equals(s1.gav, s2.gav)) {
            return null;
        }
        
        // Check filePath (key field)
        if (!Objects.equals(s1.filePath, s2.filePath)) {
            return null;
        }
        
        // Check sha1 (key field)
        if (!Objects.equals(s1.sha1, s2.sha1)) {
            return null;
        }
        
        // Check regex attributes
        if (s1.packageUrlRegex != s2.packageUrlRegex ||
            s1.gavRegex != s2.gavRegex ||
            s1.filePathRegex != s2.filePathRegex) {
            return null;
        }
        
        // Check CPEs (must match exactly)
        if (!s1.cpes.equals(s2.cpes)) {
            return null;
        }
        
        // Check CVEs (must match exactly)
        if (!s1.cves.equals(s2.cves)) {
            return null;
        }
        
        // Check vulnerability names (must match exactly)
        if (!s1.vulnerabilityNames.equals(s2.vulnerabilityNames)) {
            return null;
        }
        
        // At least one key field must be non-null
        if (s1.packageUrl == null && s1.gav == null && s1.filePath == null && s1.sha1 == null) {
            return null;
        }
        
        // Build reason string showing what matched
        StringBuilder reason = new StringBuilder("Exact match");
        if (s1.packageUrl != null) {
            reason.append(" - packageUrl: ").append(s1.packageUrl);
        }
        if (s1.gav != null) {
            reason.append(" - gav: ").append(s1.gav);
        }
        if (s1.filePath != null) {
            reason.append(" - filePath: ").append(s1.filePath);
        }
        if (s1.sha1 != null) {
            reason.append(" - sha1: ").append(s1.sha1);
        }
        if (!s1.cpes.isEmpty()) {
            reason.append(" - CPEs: ").append(s1.cpes.size()).append(" match");
        }
        if (!s1.cves.isEmpty()) {
            reason.append(" - CVEs: ").append(s1.cves.size()).append(" match");
        }
        
        return reason.toString();
    }

    /**
    * Remove suppressions from the file line-by-line to preserve formatting.
    * This avoids the XML transformer reformatting the entire file.
     */
    private static void removeSuppressionsLineByLine(String filePath, Set<Suppression> toRemove) throws Exception {
    // Read the entire file
    List<String> lines = Files.readAllLines(Paths.get(filePath));
        
    // Parse suppressions with their line ranges
    List<SuppressionLineRange> lineRanges = findSuppressionLineRanges(lines);
    
    // Determine which line ranges to remove
        Set<Integer> linesToRemove = new HashSet<>();
    for (SuppressionLineRange range : lineRanges) {
    if (toRemove.contains(range.suppression)) {
                for (int i = range.startLine; i <= range.endLine; i++) {
            linesToRemove.add(i);
        }
    }
    }
    
    // Write back only the lines we're keeping
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
    for (int i = 0; i < lines.size(); i++) {
            if (!linesToRemove.contains(i)) {
                    writer.write(lines.get(i));
                    writer.newLine();
                }
            }
        }
    }
    
    /**
     * Find the line ranges for each suppression in the file.
     */
    private static List<SuppressionLineRange> findSuppressionLineRanges(List<String> lines) throws Exception {
        List<SuppressionLineRange> ranges = new ArrayList<>();
        
        int startLine = -1;
        StringBuilder currentXml = new StringBuilder();
        
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            String trimmed = line.trim();
            
            if (trimmed.startsWith("<suppress base=\"true\">") || trimmed.equals("<suppress base=\"true\">")) {
                startLine = i;
                currentXml = new StringBuilder();
                currentXml.append(line).append("\n");
            } else if (startLine >= 0) {
                currentXml.append(line).append("\n");
                
                if (trimmed.equals("</suppress>")) {
                    // End of suppression found
                    try {
                        // Parse this suppression
                        String xmlString = currentXml.toString();
                        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                        factory.setNamespaceAware(true);
                        DocumentBuilder builder = factory.newDocumentBuilder();
                        Document doc = builder.parse(new java.io.ByteArrayInputStream(xmlString.getBytes()));
                        Element suppressElement = doc.getDocumentElement();
                        
                        Suppression suppression = new Suppression(suppressElement, "base");
                        ranges.add(new SuppressionLineRange(suppression, startLine, i));
                    } catch (Exception e) {
                        // Skip malformed suppressions
                        System.err.println("Warning: Could not parse suppression at line " + startLine + ": " + e.getMessage());
                    }
                    
                    startLine = -1;
                    currentXml = new StringBuilder();
                }
            }
        }
        
        return ranges;
    }
    
    static class SuppressionLineRange {
        final Suppression suppression;
        final int startLine;
        final int endLine;
        
        SuppressionLineRange(Suppression suppression, int startLine, int endLine) {
            this.suppression = suppression;
            this.startLine = startLine;
            this.endLine = endLine;
        }
    }

    private static Document parseXmlFile(String path) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new File(path));
    }

    private static Document parseXmlFromUrl(String urlString) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        URL url = new URL(urlString);
        
        // Read the content and wrap it in a proper XML structure
        // The generatedSuppressions.xml is a fragment, not a complete document
        StringBuilder content = new StringBuilder();
        content.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        content.append("<suppressions xmlns=\"https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd\">\n");
        
        try (InputStream is = url.openStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        
        content.append("</suppressions>\n");
        
        // Parse the wrapped content
        return builder.parse(new java.io.ByteArrayInputStream(content.toString().getBytes("UTF-8")));
    }

    private static void writeXmlFile(Document doc, String path) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
        
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(path));
        transformer.transform(source, result);
    }

    private static List<Suppression> extractSuppressions(Document doc, String source) {
        List<Suppression> suppressions = new ArrayList<>();
        NodeList nodes = doc.getElementsByTagName("suppress");
        
        for (int i = 0; i < nodes.getLength(); i++) {
            Element element = (Element) nodes.item(i);
            suppressions.add(new Suppression(element, source));
        }
        
        return suppressions;
    }

    static class Suppression {
        final String source;
        final String notes;
        final String packageUrl;
        final String gav;
        final String filePath;
        final String sha1;
        final boolean packageUrlRegex;
        final boolean gavRegex;
        final boolean filePathRegex;
        final Set<String> cpes;
        final Set<String> cves;
        final Set<String> vulnerabilityNames;
        final Element element;

        Suppression(Element element, String source) {
            this.element = element;
            this.source = source;
            this.notes = getElementText(element, "notes");
            this.packageUrl = getElementText(element, "packageUrl");
            this.gav = getElementText(element, "gav");
            this.filePath = getElementText(element, "filePath");
            this.sha1 = getElementText(element, "sha1");
            this.packageUrlRegex = hasRegexAttribute(element, "packageUrl");
            this.gavRegex = hasRegexAttribute(element, "gav");
            this.filePathRegex = hasRegexAttribute(element, "filePath");
            this.cpes = getElementTexts(element, "cpe");
            this.cves = getElementTexts(element, "cve");
            this.vulnerabilityNames = getElementTexts(element, "vulnerabilityName");
        }

        private String getElementText(Element parent, String tagName) {
            NodeList nodes = parent.getElementsByTagName(tagName);
            if (nodes.getLength() > 0) {
                return nodes.item(0).getTextContent().trim();
            }
            return null;
        }

        private boolean hasRegexAttribute(Element parent, String tagName) {
            NodeList nodes = parent.getElementsByTagName(tagName);
            if (nodes.getLength() > 0) {
                Element elem = (Element) nodes.item(0);
                String regex = elem.getAttribute("regex");
                return "true".equalsIgnoreCase(regex);
            }
            return false;
        }

        private Set<String> getElementTexts(Element parent, String tagName) {
            Set<String> texts = new HashSet<>();
            NodeList nodes = parent.getElementsByTagName(tagName);
            for (int i = 0; i < nodes.getLength(); i++) {
                String text = nodes.item(i).getTextContent().trim();
                if (!text.isEmpty()) {
                    texts.add(text);
                }
            }
            return texts;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Notes: ").append(notes != null ? notes.replaceAll("\\s+", " ").substring(0, Math.min(100, notes.length())) + "..." : "N/A").append("\n");
            
            if (packageUrl != null) {
                sb.append("PackageURL").append(packageUrlRegex ? " (regex)" : "").append(": ").append(packageUrl).append("\n");
            }
            if (gav != null) {
                sb.append("GAV").append(gavRegex ? " (regex)" : "").append(": ").append(gav).append("\n");
            }
            if (filePath != null) {
                sb.append("FilePath").append(filePathRegex ? " (regex)" : "").append(": ").append(filePath).append("\n");
            }
            if (sha1 != null) {
                sb.append("SHA1: ").append(sha1).append("\n");
            }
            if (!cpes.isEmpty()) {
                sb.append("CPEs: ").append(cpes).append("\n");
            }
            if (!cves.isEmpty()) {
                sb.append("CVEs: ").append(cves).append("\n");
            }
            if (!vulnerabilityNames.isEmpty()) {
                sb.append("Vuln Names: ").append(vulnerabilityNames).append("\n");
            }
            
            return sb.toString();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Suppression)) return false;
            Suppression that = (Suppression) o;
            return Objects.equals(packageUrl, that.packageUrl) &&
                    Objects.equals(gav, that.gav) &&
                    Objects.equals(filePath, that.filePath) &&
                    Objects.equals(sha1, that.sha1) &&
                    Objects.equals(cpes, that.cpes) &&
                    Objects.equals(cves, that.cves);
        }

        @Override
        public int hashCode() {
            return Objects.hash(packageUrl, gav, filePath, sha1, cpes, cves);
        }
    }

    static class DuplicatePair {
        final Suppression base;
        final Suppression generated;
        final String matchReason;

        DuplicatePair(Suppression base, Suppression generated, String matchReason) {
            this.base = base;
            this.generated = generated;
            this.matchReason = matchReason;
        }
    }
}
