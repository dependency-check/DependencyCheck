# Suppression File Synchronization

## Overview

DependencyCheck maintains two suppression files:
- **Base Suppression File**: `core/src/main/resources/dependencycheck-base-suppression.xml` - Manually curated suppressions that ship with releases
- **Generated Suppressions File**: Maintained on the `generatedSuppressions` branch - Auto-generated suppressions from GitHub issue reports

## Strategy

The two files serve different purposes and should remain separate:
- The **generated file** is automatically maintained via GitHub Actions when issues are reported
- The **base file** should contain only manually curated suppressions that are NOT in the generated file
- Both files are loaded at runtime, so suppressions in either file will be applied

## Synchronization Tools

Two tools are available to help keep the files in sync in case of overlap (current situation as of Nov 10, 2025):

### 1. Git History Analyzer

The `SuppressionSyncAnalyzer` analyzes git history of the generated suppressions file to find suppressions that were **modified or deleted**:

- ✅ Focuses on intentional changes (not just duplicates)
- ✅ Provides git commit context (why was it changed?)
- ✅ Catches consolidations (e.g., 20 individual rules → 1 broad rule)
- ✅ Shows GitHub commit links for review
- ✅ Handles the "V" option to view commits in browser

**Interactive mode** (recommended):
```bash
./deduplicate-suppressions.sh
# or explicitly:
./deduplicate-suppressions.sh analyzer
```

This will:
1. Fetch the latest from the `generatedSuppressions` branch
2. Analyze git history for modifications/deletions
3. Check if old versions exist in base file
4. Interactively show each one with:
   - What's currently in base
   - What happened in generated (modified/deleted)
   - Git commit info with clickable GitHub link
5. Let you decide: Remove, Keep, View commit, Quit, or Auto-remove all

**Non-interactive mode**:
```bash
./deduplicate-suppressions.sh analyzer --non-interactive
```

This automatically removes ALL obsolete suppressions from base.

### 2. Duplicate Detector (Legacy)

The `SuppressionDeduplicator` finds exact duplicates between the two files. This is less sophisticated but faster for simple cases.

**Interactive mode**:
```bash
./deduplicate-suppressions.sh deduplicator
```

**Non-interactive mode**:
```bash
./deduplicate-suppressions.sh deduplicator --non-interactive
```

### Backup

The tool automatically creates a backup of the base suppression file before making changes:
- Backup location: `dependencycheck-base-suppression.xml.backup`

## How Issues Are Detected

### Git History Analyzer
Finds suppressions in base that match the OLD version from git history where:
1. The suppression was **deleted** from generated
2. OR the suppression was **modified** in generated (indicating consolidation or correction)

### Duplicate Detector
Two suppressions are considered duplicates if:
1. They have matching **key fields** (packageUrl, gav, filePath, or sha1)
2. AND they have overlapping **CPEs**, **CVEs**, or **vulnerability names**

## Implementation Details

- `utils/src/main/java/org/owasp/dependencycheck/utils/SuppressionSyncAnalyzer.java` - Git history analyzer
- `utils/src/main/java/org/owasp/dependencycheck/utils/SuppressionDeduplicator.java` - Duplicate detector
- `utils/src/test/java/org/owasp/dependencycheck/utils/SuppressionSyncAnalyzerTest.java` - Tests for git diff parsing

### Running Tests

To verify the git diff parsing logic works correctly:

```bash
mvn -pl utils test -Dtest=SuppressionSyncAnalyzerTest
```
