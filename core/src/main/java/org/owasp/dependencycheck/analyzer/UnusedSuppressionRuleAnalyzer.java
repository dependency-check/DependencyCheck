/*
 * This file is part of dependency-check-core.
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
 * Copyright (c) 2022 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.util.List;
import org.owasp.dependencycheck.Engine;
import static org.owasp.dependencycheck.analyzer.AbstractSuppressionAnalyzer.SUPPRESSION_OBJECT_KEY;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.xml.suppression.SuppressionRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Log the unused suppression rules.
 *
 * @author Jeremy Long
 */
public class UnusedSuppressionRuleAnalyzer extends AbstractAnalyzer {

    /**
     * Exception message.
     */
    protected static final String EXCEPTION_MSG = "There are %d unused suppression rule(s): check logs.";

    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(UnusedSuppressionRuleAnalyzer.class);
    /**
     * A flag indicating whether or not the unused vulnerabilities have already
     * been reported.
     */
    private boolean reported = false;
    /**
     * A flag indicating whether build should fail on unused suppression rule
     */
    private boolean shouldFailForUnusedSuppressionRule = false;
    /**
     * unused suppression rule count
     */
    private int unusedSuppressionRuleCount = 0;

    @Override
    public synchronized void initialize(Settings settings) {
        super.initialize(settings);
        if (settings.getBoolean(Settings.KEYS.FAIL_ON_UNUSED_SUPPRESSION_RULE, false)) {
            this.shouldFailForUnusedSuppressionRule = true;
        }
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (!reported) {
            checkUnusedRules(engine);
            reported = true;
            if (unusedSuppressionRuleCount > 0 && failsForUnusedSuppressionRule()) {
                final String message = String.format(EXCEPTION_MSG, unusedSuppressionRuleCount);
                LOGGER.error(message);
                throw new AnalysisException(message);
            }
        }
    }

    /**
     * check unused suppression RULES.
     *
     * @param engine a reference to the ODC engine
     */
    protected void checkUnusedRules(Engine engine) {
        if (engine.hasObject(SUPPRESSION_OBJECT_KEY)) {
            @SuppressWarnings("unchecked")
            final List<SuppressionRule> rules = (List<SuppressionRule>) engine.getObject(SUPPRESSION_OBJECT_KEY);
            rules.forEach((rule) -> {
                if (!rule.isMatched() && !rule.isBase()) {
                    final String message = String.format("Suppression Rule had zero matches: %s", rule);
                    if (failsForUnusedSuppressionRule()) {
                        LOGGER.error(message);
                    } else {
                        LOGGER.info(message);
                    }
                    increaseUnusedSuppressionRuleCount();
                }
            });
        }
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        //technically incorrect - but we will reuse the enabled key for this analyzer
        return Settings.KEYS.ANALYZER_VULNERABILITY_SUPPRESSION_ENABLED;
    }

    @Override
    public String getName() {
        return "Unused Suppression Rule Analyzer";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINAL;
    }

    @Override
    public boolean supportsParallelProcessing() {
        return false;
    }

    /**
     * increases the count of unused suppression rules.
     */
    public void increaseUnusedSuppressionRuleCount() {
        unusedSuppressionRuleCount++;
    }

    /**
     * @return the count of unused suppression rules.
     */
    public int getUnusedSuppressionRuleCount() {
        return unusedSuppressionRuleCount;
    }

    /**
     * @return whether the analyzer will fail for a unused suppression rule.
     */
    public boolean failsForUnusedSuppressionRule() {
        return shouldFailForUnusedSuppressionRule;
    }
}
