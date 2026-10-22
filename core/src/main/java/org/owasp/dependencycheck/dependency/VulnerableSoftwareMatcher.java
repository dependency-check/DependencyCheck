package org.owasp.dependencycheck.dependency;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;

import us.springett.parsers.cpe.Cpe;

public final class VulnerableSoftwareMatcher {

    private VulnerableSoftwareMatcher() {
    }

    public enum Outcome {
        /** At least one entry matches the CPE. */
        MATCH,
        /** Every supplied entry was evaluated, none matched. */
        NO_MATCH,
        /** Fallback (Fail open) */
        INCONCLUSIVE
    }

    public static final class MatchResult {
        private final Outcome outcome;
        private final String reason;
        private final VulnerableSoftware selectedMatch;
        private final List<VulnerableSoftware> matchingSoftware;
        private final List<VulnerableSoftware> retainedSoftware;

        private MatchResult(Outcome outcome, String reason, VulnerableSoftware selectedMatch,
                List<VulnerableSoftware> matchingSoftware,
                List<VulnerableSoftware> retainedSoftware) {

            this.outcome = Objects.requireNonNull(outcome, "outcome");
            Objects.requireNonNull(matchingSoftware, "matchingSoftware");
            Objects.requireNonNull(retainedSoftware, "retainedSoftware");

            if (outcome == Outcome.INCONCLUSIVE) {

                if (reason == null || reason.trim().isEmpty()) {
                    throw new IllegalArgumentException("INCONCLUSIVE requires a reason");
                }

            } else if (reason != null) {
                throw new IllegalArgumentException("Only INCONCLUSIVE may have a reason");
            }

            if ((outcome == Outcome.MATCH) != (selectedMatch != null)) {
                throw new IllegalArgumentException("MATCH requires a selected match");
            }

            if (selectedMatch != null && !matchingSoftware.contains(selectedMatch)) {
                throw new IllegalArgumentException("selected match must be in matchingSoftware");
            }

            if (!retainedSoftware.containsAll(matchingSoftware)) {
                throw new IllegalArgumentException("matches must be retained software entries");
            }
            this.reason = reason;
            this.selectedMatch = selectedMatch;
            this.matchingSoftware = List.copyOf(matchingSoftware);
            this.retainedSoftware = List.copyOf(retainedSoftware);
        }

        public Outcome getOutcome() {
            return outcome;
        }

        /**
         * Should only be filled up for inconclusive i.e the reason why it is
         * inconclusive which will help with debugging.
         */
        public String getReason() {
            return reason;
        }

        public boolean isMatch() {
            return outcome == Outcome.MATCH;
        }

        public boolean shouldRetain() {
            return outcome != Outcome.NO_MATCH;
        }

        public VulnerableSoftware getSelectedMatch() {
            return selectedMatch;
        }

        public List<VulnerableSoftware> getMatchingSoftware() {
            return matchingSoftware;
        }

        public List<VulnerableSoftware> getRetainedSoftware() {
            return retainedSoftware;
        }
    }

    public static MatchResult match(Cpe dependencyCpe,
            Collection<VulnerableSoftware> software,
            String dependencyEcosystem) {

        Objects.requireNonNull(dependencyCpe, "dependencyCpe");

        if (software == null || software.isEmpty()) {
            return inconclusive(
                    "No vulnerable-software evidence supplied",
                    List.of(), List.of());
        }

        final List<VulnerableSoftware> candidates = new ArrayList<>(software);

        if (candidates.removeIf(Objects::isNull)) {
            return inconclusive(
                    "Vulnerable-software evidence contains a null entry",
                    candidates, List.of());
        }

        final String ecosystem = Ecosystem.fromTargetSoftware(dependencyEcosystem);

        final List<VulnerableSoftware> matches = new ArrayList<>();

        try {
            for (VulnerableSoftware entry : candidates) {
                if (entry.matches(dependencyCpe)) {
                    matches.add(entry);
                }
            }

            if (matches.isEmpty()) {
                return new MatchResult(
                        Outcome.NO_MATCH, null, null, matches, candidates);
            }

            matches.sort(Comparator
                    .comparingInt((VulnerableSoftware entry) -> runtimeRank(ecosystem, entry.getTargetSw()))
                    .thenComparing(Comparator.naturalOrder()));

            final VulnerableSoftware selected = matches.get(0);

            if (runtimeRank(ecosystem, selected.getTargetSw()) == 2) {
                return inconclusive(
                        "All matching software entries target a different "
                                + "recognized ecosystem",
                        candidates, matches);
            }

            return new MatchResult(
                    Outcome.MATCH, null, selected, matches, candidates);

        } catch (RuntimeException ex) {
            return inconclusive(
                    "Unable to evaluate vulnerable-software evidence ("
                            + ex.getClass().getSimpleName() + ")",
                    candidates, matches);
        }
    }

    /**
     * 0. Exact recognised ecosystem
     * 1. Unknown/unspecified 
     * 2. recognized but different runtime.
     */
    private static int runtimeRank(String wanted, String target) {
        final String actual = Ecosystem.fromTargetSoftware(target);

        // Prefer an exact ecosystem match.
        if (wanted != null && wanted.equals(actual)) {
            return 0;
        }

        // An unknown ecosystem is preferable to a known mismatch.
        if (wanted == null || actual == null) {
            return 1;
        }

        // Both ecosystems are known but incompatible.
        return 2;
    }

    private static MatchResult inconclusive(String reason,
            List<VulnerableSoftware> candidates,
            List<VulnerableSoftware> matches) {

        return new MatchResult(
                Outcome.INCONCLUSIVE, reason, null, matches, candidates);
    }

}
