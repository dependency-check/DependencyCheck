package org.owasp.dependencycheck.analyzer;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import static org.owasp.dependencycheck.analyzer.AbstractSuppressionAnalyzer.SUPPRESSION_OBJECT_KEY;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import static org.owasp.dependencycheck.analyzer.UnusedSuppressionRuleAnalyzer.EXCEPTION_MSG;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.xml.suppression.SuppressionRule;
import org.owasp.dependencycheck.xml.suppression.PropertyType;

public class UnusedSuppressionRuleAnalyzerTest extends BaseTest {
	private static final String NAME = "Unused Suppression Rule Analyzer";
	private static final String PACKAGE_NAME = "CoolAsACucumber";
	private static final String EXPECTED_EX = "should have thrown an AnalysisException";

    @Test
    public void testGetName() {
        UnusedSuppressionRuleAnalyzer analyzer = new UnusedSuppressionRuleAnalyzer();
        assertEquals(NAME, analyzer.getName());
    }

    @Test
    public void testException() throws Exception {
		boolean shouldFail = true;
		Dependency dependency10 = getDependency("1.0");
		Dependency dependency11 = getDependency("1.1");
		
		UnusedSuppressionRuleAnalyzer analyzer = getAnalyzer(shouldFail);
		Engine engine = getEngine(true, false, dependency10, dependency11);
		try {
			analyzer.analyzeDependency(dependency10, engine);
			throw new Exception("should have thrown an AnalysisException");
		} catch(AnalysisException ok){
			assertEquals(String.format(EXCEPTION_MSG, 1), ok.getMessage());
		}
		
		// no exception
		shouldFail = false;
		analyzer = getAnalyzer(shouldFail);
		engine = getEngine(true, false, dependency10, dependency11);
		analyzer.analyzeDependency(dependency10, engine);
    	assertEquals(1, analyzer.getUnusedSuppressionRuleCount());
	}
	
    @Test
    public void testCheckUnusedRules() throws Exception {
		// flag unset
		boolean shouldFail = false;
		Dependency dependency10 = getDependency("1.0");
		Dependency dependency11 = getDependency("1.1");
		
		// a run without any suppression rule ➫ no unused suppression
		checkUnusedRules(shouldFail, 0, false, false, dependency10);

		// a run without no matching rule ➫ one unused suppression
		checkUnusedRules(shouldFail, 1, true, false, dependency10, dependency11);

		// a run with the vulnerable package ➫ no unused suppression
		checkUnusedRules(shouldFail, 0, true, true, dependency10, dependency11);

			
		// set flag
		shouldFail = true;

		// a run without any suppression rule ➫ no unused suppression
		checkUnusedRules(shouldFail, 0, false, false, dependency10);

		// a run without no matching rule ➫ one unused suppression
		checkUnusedRules(shouldFail, 1, true, false, dependency10, dependency11);

		// a run with the vulnerable package ➫ no unused suppression
		checkUnusedRules(shouldFail, 0, true, true, dependency10, dependency11);
    }
	
	private void checkUnusedRules(boolean shouldFail, int expectedCount, 
		boolean withSuppressionRules, boolean matching,
		Dependency ... dependencies) throws Exception {
        UnusedSuppressionRuleAnalyzer analyzer = getAnalyzer(shouldFail);
		assertNotNull(analyzer);
		Engine engine = getEngine(withSuppressionRules, matching, dependencies);
		analyzer.checkUnusedRules(engine);
		assertEquals(expectedCount, analyzer.getUnusedSuppressionRuleCount());
	}
	
		
	private Dependency getDependency(String type, String namespace, String name, String version) throws Exception {
        Dependency dependency = new Dependency();
		Identifier id = new PurlIdentifier(type,namespace,name,version,Confidence.HIGHEST);
        dependency.addSoftwareIdentifier(id);
		return dependency;
	}
	
	private Dependency getDependency(String version) throws Exception {
		return getDependency("maven", "test", PACKAGE_NAME, version);
	}	

	
	private Engine getEngine(boolean hasSuppressionRules, boolean matching, Dependency ... dependencies) throws Exception {
        Engine engine = new Engine(getSettings());
		List<Dependency> dependencyList = new ArrayList<>();
		if (dependencies!=null) {
			for(Dependency d : dependencies)
				dependencyList.add(d);
		}
		engine.setDependencies(dependencyList);
		if(!hasSuppressionRules) return engine;
		List<SuppressionRule> rules = new ArrayList<>();
		rules.add(getSuppressionRule(matching));
		engine.putObject(SUPPRESSION_OBJECT_KEY,rules);
		return engine;
	}
	
	private UnusedSuppressionRuleAnalyzer getAnalyzer(boolean flag) throws AnalysisException {
        UnusedSuppressionRuleAnalyzer analyzer = new UnusedSuppressionRuleAnalyzer();
		assertNotNull(analyzer);
		
		Settings settings = getSettings();
        settings.setBoolean(Settings.KEYS.FAIL_ON_UNUSED_SUPPRESSION_RULE, flag);
        analyzer.initialize(settings);
        assertEquals(flag, analyzer.failsForUnusedSuppressionRule());
        assertEquals(0, analyzer.getUnusedSuppressionRuleCount());
		
		return analyzer;		
	}
	
	private SuppressionRule getSuppressionRule(boolean matching) {
        SuppressionRule instance = new SuppressionRule();
		instance.addVulnerabilityName(getPropertyType("CVE-2023-5072", false, false));
		instance.setPackageUrl(getPropertyType("^pkg:maven/test." + PACKAGE_NAME + "." + matching, false, false));
		instance.addCpe(getPropertyType(PACKAGE_NAME, false, false));
		instance.setBase(false);
		instance.setMatched(matching);
		return instance;
    }
	
	private PropertyType getPropertyType(String value, boolean regex, boolean caseSensitive) {
		PropertyType property = new PropertyType();
		property.setValue(value);
		property.setRegex(regex);
		property.setCaseSensitive(caseSensitive);
		return property;
	}
	

}
