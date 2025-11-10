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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Analyzes git history of the generated suppressions file to find suppressions that were
 * modified or deleted, then checks if the old versions exist in the base file.
 *
 * This approach is superior to simple duplicate detection because it:
 * - Focuses on suppressions that were intentionally changed/removed (not just duplicates)
 * - Provides context via git commit messages
 * - Catches consolidations that wouldn't be detected as exact duplicates
 */
public class SuppressionSyncAnalyzer {

    private static final String GITHUB_BASE = "https://github.com/dependency-check/DependencyCheck";
    private static final String GENERATED_BRANCH = "generatedSuppressions";
    private static final String GENERATED_FILE = "generatedSuppressions.xml";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java SuppressionSyncAnalyzer <path-to-base-suppression.xml> [--non-interactive]");
            System.err.println("  --non-interactive: Remove all obsolete suppressions without prompting");
            System.exit(1);
        }

        String basePath = args[0];
        boolean interactive = true;

        if (args.length > 1 && "--non-interactive".equals(args[1])) {
            interactive = false;
        }

        System.out.println("=== DependencyCheck Suppression Sync Analyzer ===\n");
        System.out.println("This tool analyzes git history of the generated suppressions file");
        System.out.println("to find suppressions that were modified or deleted.\n");

        // Check if we're in a git repository
        if (!new File(".git").exists()) {
            System.err.println("Error: Must be run from the root of the DependencyCheck git repository");
            System.exit(1);
        }

        System.out.println("Base suppression file: " + basePath);
        System.out.println();

        // Fetch the latest from the generatedSuppressions branch
        System.out.println("Fetching latest from generatedSuppressions branch...");
        try {
            execGitCommand("git", "fetch", "origin", GENERATED_BRANCH + ":" + GENERATED_BRANCH);
        } catch (Exception e) {
            System.err.println("Warning: Could not fetch latest. Using local branch. (" + e.getMessage() + ")");
        }

        // Get git log for the generated file
        System.out.println("Analyzing git history of generated suppressions...");
        List<GitCommit> commits = getCommitsAffectingFile(GENERATED_BRANCH, GENERATED_FILE);
        System.out.println("Found " + commits.size() + " commits affecting generated suppressions\n");

        // Parse base file
        System.out.println("Parsing base suppression file...");
        Document baseDoc = parseXmlFile(basePath);
        List<Suppression> baseSuppressions = extractSuppressions(baseDoc);
        System.out.println("Found " + baseSuppressions.size() + " suppressions in base file\n");

        // Analyze each commit for modifications/deletions
        System.out.println("Analyzing commits for modifications and deletions...");
        List<ObsoleteSuppression> obsolete = findObsoleteSuppressions(commits, baseSuppressions);

        if (obsolete.isEmpty()) {
            System.out.println("No obsolete suppressions found in base file!");
            System.out.println("Base file is in sync with generated file changes.");
            return;
        }

        System.out.println("Found " + obsolete.size() + " suppressions in base that were modified/deleted in generated\n");

        // Process obsolete suppressions
        Set<Suppression> toRemoveFromBase = new HashSet<>();

        if (interactive) {
            toRemoveFromBase = processInteractive(obsolete);
        } else {
            System.out.println("Non-interactive mode: Removing all obsolete suppressions from base file");
            toRemoveFromBase = obsolete.stream()
                    .map(o -> o.baseSuppression)
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
        removesuppressionsLineByLine(basePath, toRemoveFromBase);

        System.out.println("\n=== Complete ===");
        System.out.println("Removed " + toRemoveFromBase.size() + " obsolete suppressions from base file");
        System.out.println("Backup saved to: " + backupPath);
        
        // Print summary of commits
        printRemovalSummary(obsolete, toRemoveFromBase);
    }
    
    private static void printRemovalSummary(List<ObsoleteSuppression> obsolete, Set<Suppression> removed) {
        System.out.println("\n=== Removal Summary ===");
        
        // Group by commit
        Map<String, List<ObsoleteSuppression>> byCommit = new LinkedHashMap<>();
        for (ObsoleteSuppression obs : obsolete) {
            if (removed.contains(obs.baseSuppression)) {
                byCommit.computeIfAbsent(obs.commit.shortHash, k -> new ArrayList<>()).add(obs);
            }
        }
        
        if (byCommit.isEmpty()) {
            System.out.println("No suppressions were removed.");
            return;
        }
        
        System.out.println("Suppressions removed based on changes from commits:");
        for (Map.Entry<String, List<ObsoleteSuppression>> entry : byCommit.entrySet()) {
            String hash = entry.getKey();
            List<ObsoleteSuppression> items = entry.getValue();
            ObsoleteSuppression first = items.get(0);
            
            System.out.println("\n  " + hash + " - " + first.commit.message);
            System.out.println("    Date: " + first.commit.date);
            System.out.println("    URL: " + GITHUB_BASE + "/commit/" + first.commit.fullHash);
            System.out.println("    Removed " + items.size() + " suppression(s)");
        }
        
        System.out.println("\n" + removed.size() + " total suppression(s) removed from " + byCommit.size() + " commit(s)");
    }

    private static Set<Suppression> processInteractive(List<ObsoleteSuppression> obsolete) throws IOException {
        Set<Suppression> toRemoveFromBase = new HashSet<>();
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        for (int i = 0; i < obsolete.size(); i++) {
            ObsoleteSuppression obs = obsolete.get(i);

            System.out.println("=".repeat(100));
            System.out.println("Obsolete Suppression " + (i + 1) + " of " + obsolete.size());
            System.out.println("=".repeat(100));

            System.out.println("\n[CURRENT IN BASE FILE]");
            System.out.println(obs.baseSuppression.toDetailedString());

            System.out.println("\n[WHAT HAPPENED IN GENERATED FILE]");
            if (obs.wasDeleted) {
                System.out.println("✗ DELETED in commit " + obs.commit.shortHash);
            } else {
                System.out.println("✎ MODIFIED in commit " + obs.commit.shortHash);
                if (obs.newVersion != null) {
                    System.out.println("\n[NEW VERSION IN GENERATED]");
                    System.out.println(obs.newVersion);
                }
            }

            System.out.println("\n[COMMIT INFO]");
            System.out.println("Commit: " + obs.commit.shortHash);
            System.out.println("Date: " + obs.commit.date);
            System.out.println("Message: " + obs.commit.message);
            System.out.println("URL: " + GITHUB_BASE + "/commit/" + obs.commit.fullHash);

            System.out.println("\nWhat would you like to do?");
            System.out.println("  (R) Remove from base file (recommended)");
            System.out.println("  (K) Keep in base file");
            System.out.println("  (V) View commit in browser");
            System.out.println("  (Q) Quit without saving");
            System.out.println("  (A) Remove all remaining obsolete suppressions");
            System.out.print("\nChoice [R/K/V/Q/A]: ");

            String choice = reader.readLine().trim().toUpperCase();

            switch (choice) {
                case "R":
                    toRemoveFromBase.add(obs.baseSuppression);
                    System.out.println("✓ Will remove from base\n");
                    break;
                case "K":
                    System.out.println("✓ Will keep in base\n");
                    break;
                case "V":
                    String url = GITHUB_BASE + "/commit/" + obs.commit.fullHash;
                    System.out.println("Opening: " + url);
                    openBrowser(url);
                    i--; // Re-show this suppression
                    continue;
                case "Q":
                    System.out.println("\nQuitting without changes.");
                    System.exit(0);
                    break;
                case "A":
                    toRemoveFromBase.add(obs.baseSuppression);
                    for (int j = i + 1; j < obsolete.size(); j++) {
                        toRemoveFromBase.add(obsolete.get(j).baseSuppression);
                    }
                    System.out.println("✓ Will remove all remaining obsolete suppressions\n");
                    return toRemoveFromBase;
                default:
                    System.out.println("Invalid choice, skipping.\n");
            }
        }

        return toRemoveFromBase;
    }

    private static void openBrowser(String url) {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("mac")) {
                Runtime.getRuntime().exec("open " + url);
            } else if (os.contains("nux")) {
                Runtime.getRuntime().exec("xdg-open " + url);
            } else if (os.contains("win")) {
                Runtime.getRuntime().exec("rundll32 url.dll,FileProtocolHandler " + url);
            }
        } catch (IOException e) {
            System.err.println("Could not open browser: " + e.getMessage());
        }
    }

    private static List<ObsoleteSuppression> findObsoleteSuppressions(
            List<GitCommit> commits, List<Suppression> baseSuppressions) throws Exception {

        List<ObsoleteSuppression> obsolete = new ArrayList<>();
        Set<String> processedKeys = new HashSet<>();

        for (GitCommit commit : commits) {
            // Get the diff for this commit
            String diff = getFileDiffForCommit(commit.fullHash, GENERATED_BRANCH, GENERATED_FILE);
//            System.out.println("Analyzing commit " + commit.shortHash + " - " + diff);
            // Parse deleted/modified suppressions from diff
            List<DiffSuppression> deletions = parseDeletedSuppressions(diff);
            System.out.println("Found " + deletions.size() + " deleted/modified suppressions in this commit");
            for (DiffSuppression deletion : deletions) {
                System.out.println("Processing deleted/modified suppression: " + deletion.toString());
                // Check if this suppression exists in base
                Suppression matchInBase = findMatchInBase(deletion, baseSuppressions);

                if (matchInBase != null) {
                    String key = matchInBase.getKey();
                    if (!processedKeys.contains(key)) {
                        processedKeys.add(key);

                        // Try to find if there's a new version in current generated file
                        String newVersion = findNewVersionInGenerated(deletion);

                        obsolete.add(new ObsoleteSuppression(
                                matchInBase,
                                commit,
                                deletion.wasModified ? newVersion : null,
                                !deletion.wasModified
                        ));
                    }
                }
            }
        }

        return obsolete;
    }

    private static String findNewVersionInGenerated(DiffSuppression deletion) {
        // This would require parsing the current generated file
        // For now, return null - can be enhanced later
        return null;
    }

    private static Suppression findMatchInBase(DiffSuppression deletion, List<Suppression> baseSuppressions) {
        for (Suppression base : baseSuppressions) {
            if (deletion.matches(base)) {
                return base;
            }
        }
        return null;
    }

    private static List<DiffSuppression> parseDeletedSuppressions(String diff) {
        List<DiffSuppression> result = new ArrayList<>();
        
        // Split diff into lines
        String[] lines = diff.split("\n");
        
        StringBuilder currentSuppression = new StringBuilder();
        boolean inSuppression = false;
        boolean hasDeletedContent = false;
        
        for (String line : lines) {
            String trimmed = line.trim();
            
            // Check if we're entering a suppress block (with or without '-' prefix)
            if (trimmed.equals("<suppress base=\"true\">") || 
                (line.startsWith("-") && line.substring(1).trim().equals("<suppress base=\"true\">"))) {
                // Start of a new suppression
                inSuppression = true;
                hasDeletedContent = line.startsWith("-");
                currentSuppression = new StringBuilder();
                
                // Add the opening tag (without the '-' if present)
                String content = line.startsWith("-") ? line.substring(1) : line;
                currentSuppression.append(content.trim()).append("\n");
                
            } else if (inSuppression) {
                // We're inside a suppression block
                boolean isDeletedLine = line.startsWith("-");
                
                if (isDeletedLine) {
                    hasDeletedContent = true;
                    String content = line.substring(1); // Remove the '-'
                    currentSuppression.append(content.trim()).append("\n");
                    
                    // Check if we've reached the end of this suppression
                    if (content.trim().equals("</suppress>")) {
                        if (hasDeletedContent) {
                            try {
                                DiffSuppression ds = DiffSuppression.fromXmlString(currentSuppression.toString());
                                ds.wasModified = false;
                                result.add(ds);
                            } catch (Exception e) {
                                // Skip malformed suppressions
                                System.err.println("Warning: Could not parse suppression: " + e.getMessage());
                            }
                        }
                        
                        inSuppression = false;
                        hasDeletedContent = false;
                        currentSuppression = new StringBuilder();
                    }
                } else if (trimmed.equals("</suppress>")) {
                    // Context line showing end of suppression
                    currentSuppression.append(trimmed).append("\n");
                    
                    // If we had deleted content, this is a deletion
                    if (hasDeletedContent) {
                        try {
                            DiffSuppression ds = DiffSuppression.fromXmlString(currentSuppression.toString());
                            ds.wasModified = false;
                            result.add(ds);
                        } catch (Exception e) {
                            System.err.println("Warning: Could not parse suppression: " + e.getMessage());
                        }
                    }
                    
                    inSuppression = false;
                    hasDeletedContent = false;
                    currentSuppression = new StringBuilder();
                } else if (!line.startsWith("+")) {
                    // Context line (no + or -)
                    currentSuppression.append(trimmed).append("\n");
                } else {
                    // Hit an addition line - if we had deleted content, this might be a modification
                    // For now, if we had any deleted content, treat it as a deletion
                    if (hasDeletedContent && trimmed.equals("</suppress>")) {
                        try {
                            DiffSuppression ds = DiffSuppression.fromXmlString(currentSuppression.toString());
                            ds.wasModified = true;
                            result.add(ds);
                        } catch (Exception e) {
                            System.err.println("Warning: Could not parse suppression: " + e.getMessage());
                        }
                        
                        inSuppression = false;
                        hasDeletedContent = false;
                        currentSuppression = new StringBuilder();
                    }
                }
            }
        }
        
        return result;
    }

    private static String getFileDiffForCommit(String commitHash, String branch, String file) throws Exception {
        // Get the diff for just this file in this commit
        return execGitCommand("git", "show", commitHash, "--", file);
    }

    private static List<GitCommit> getCommitsAffectingFile(String branch, String file) throws Exception {
        // Get commits that modified the file, in reverse chronological order
        // Using simple format without quotes to avoid parsing issues
        String logOutput = execGitCommand("git", "log", "--pretty=format:%H|%h|%ai|%s", branch, "--", file);

        List<GitCommit> commits = new ArrayList<>();
        for (String line : logOutput.split("\n")) {
            if (line.trim().isEmpty()) continue;

            String[] parts = line.split("\\|", 4);
            if (parts.length == 4) {
                commits.add(new GitCommit(
                        parts[0].trim(),
                        parts[1].trim(),
                        parts[2].trim(),
                        parts[3].trim()
                ));
            }
        }

        return commits;
    }

    private static String execGitCommand(String... args) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(args);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Git command failed: " + String.join(" ", args) + "\n" + output);
        }

        return output.toString();
    }

    private static void removeSuppressions(Document doc, Set<Suppression> toRemove) {
        // This method is no longer needed since we do line-based removal
        // Kept for compatibility but does nothing
    }

    /**
     * Remove suppressions from the file line-by-line to preserve formatting.
     * This avoids the XML transformer reformatting the entire file.
     */
    private static void removesuppressionsLineByLine(String filePath, Set<Suppression> toRemove) throws Exception {
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
                        
                        Suppression suppression = new Suppression(suppressElement);
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

    private static List<Suppression> extractSuppressions(Document doc) {
        List<Suppression> suppressions = new ArrayList<>();
        NodeList nodes = doc.getElementsByTagName("suppress");

        for (int i = 0; i < nodes.getLength(); i++) {
            Element element = (Element) nodes.item(i);
            suppressions.add(new Suppression(element));
        }

        return suppressions;
    }

    static class GitCommit {
        final String fullHash;
        final String shortHash;
        final String date;
        final String message;

        GitCommit(String fullHash, String shortHash, String date, String message) {
            this.fullHash = fullHash;
            this.shortHash = shortHash;
            this.date = date;
            this.message = message;
        }
    }

    static class ObsoleteSuppression {
        final Suppression baseSuppression;
        final GitCommit commit;
        final String newVersion;
        final boolean wasDeleted;

        ObsoleteSuppression(Suppression baseSuppression, GitCommit commit,
                            String newVersion, boolean wasDeleted) {
            this.baseSuppression = baseSuppression;
            this.commit = commit;
            this.newVersion = newVersion;
            this.wasDeleted = wasDeleted;
        }
    }

    static class DiffSuppression {
        String packageUrl;
        String gav;
        String filePath;
        String sha1;
        Set<String> cpes = new HashSet<>();
        Set<String> cves = new HashSet<>();
        boolean wasModified;

        static DiffSuppression fromXmlString(String xml) throws Exception {
            // Simple parsing of XML string
            DiffSuppression ds = new DiffSuppression();

            ds.packageUrl = extractValue(xml, "packageUrl");
            ds.gav = extractValue(xml, "gav");
            ds.filePath = extractValue(xml, "filePath");
            ds.sha1 = extractValue(xml, "sha1");
            ds.cpes = extractValues(xml, "cpe");
            ds.cves = extractValues(xml, "cve");

            return ds;
        }

        private static String extractValue(String xml, String tag) {
            Pattern p = Pattern.compile("<" + tag + "[^>]*>([^<]+)</" + tag + ">");
            Matcher m = p.matcher(xml);
            return m.find() ? m.group(1).trim() : null;
        }

        private static Set<String> extractValues(String xml, String tag) {
            Set<String> values = new HashSet<>();
            Pattern p = Pattern.compile("<" + tag + "[^>]*>([^<]+)</" + tag + ">");
            Matcher m = p.matcher(xml);
            while (m.find()) {
                values.add(m.group(1).trim());
            }
            return values;
        }

        boolean matches(Suppression s) {
            // Match on key fields
            if (packageUrl != null && packageUrl.equals(s.packageUrl)) {
                return hasOverlappingSuppressions(s);
            }
            if (gav != null && gav.equals(s.gav)) {
                return hasOverlappingSuppressions(s);
            }
            if (filePath != null && filePath.equals(s.filePath)) {
                return hasOverlappingSuppressions(s);
            }
            if (sha1 != null && sha1.equals(s.sha1)) {
                return true;
            }
            return false;
        }

        private boolean hasOverlappingSuppressions(Suppression s) {
            Set<String> commonCpes = new HashSet<>(cpes);
            commonCpes.retainAll(s.cpes);

            Set<String> commonCves = new HashSet<>(cves);
            commonCves.retainAll(s.cves);

            return !commonCpes.isEmpty() || !commonCves.isEmpty() ||
                    (cpes.isEmpty() && s.cpes.isEmpty() && cves.isEmpty() && s.cves.isEmpty());
        }
    }

    static class Suppression {
        final String notes;
        final String packageUrl;
        final String gav;
        final String filePath;
        final String sha1;
        final Set<String> cpes;
        final Set<String> cves;
        final Set<String> vulnerabilityNames;
        final Element element;

        Suppression(Element element) {
            this.element = element;
            this.notes = getElementText(element, "notes");
            this.packageUrl = getElementText(element, "packageUrl");
            this.gav = getElementText(element, "gav");
            this.filePath = getElementText(element, "filePath");
            this.sha1 = getElementText(element, "sha1");
            this.cpes = getElementTexts(element, "cpe");
            this.cves = getElementTexts(element, "cve");
            this.vulnerabilityNames = getElementTexts(element, "vulnerabilityName");
        }

        String getKey() {
            if (packageUrl != null) return "packageUrl:" + packageUrl;
            if (gav != null) return "gav:" + gav;
            if (filePath != null) return "filePath:" + filePath;
            if (sha1 != null) return "sha1:" + sha1;
            return "unknown";
        }

        private String getElementText(Element parent, String tagName) {
            NodeList nodes = parent.getElementsByTagName(tagName);
            if (nodes.getLength() > 0) {
                return nodes.item(0).getTextContent().trim();
            }
            return null;
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

        String toDetailedString() {
            StringBuilder sb = new StringBuilder();
            
            if (notes != null) {
                sb.append("Notes: ").append(notes.replaceAll("\\s+", " ")).append("\n\n");
            }

            if (packageUrl != null) {
                sb.append("PackageURL: ").append(packageUrl).append("\n");
            }
            if (gav != null) {
                sb.append("GAV: ").append(gav).append("\n");
            }
            if (filePath != null) {
                sb.append("FilePath: ").append(filePath).append("\n");
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
                sb.append("Vulnerability Names: ").append(vulnerabilityNames).append("\n");
            }

            return sb.toString();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Suppression)) return false;
            Suppression that = (Suppression) o;
            return getKey().equals(that.getKey());
        }

        @Override
        public int hashCode() {
            return Objects.hash(getKey());
        }
    }
}
