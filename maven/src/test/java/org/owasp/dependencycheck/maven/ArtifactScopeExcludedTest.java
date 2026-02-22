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
 * Copyright (c) 2017 Josh Cain. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.owasp.dependencycheck.utils.Filter;

import java.util.Arrays;
import java.util.Collection;

import static org.apache.maven.artifact.Artifact.SCOPE_COMPILE;
import static org.apache.maven.artifact.Artifact.SCOPE_COMPILE_PLUS_RUNTIME;
import static org.apache.maven.artifact.Artifact.SCOPE_IMPORT;
import static org.apache.maven.artifact.Artifact.SCOPE_PROVIDED;
import static org.apache.maven.artifact.Artifact.SCOPE_RUNTIME;
import static org.apache.maven.artifact.Artifact.SCOPE_RUNTIME_PLUS_SYSTEM;
import static org.apache.maven.artifact.Artifact.SCOPE_SYSTEM;
import static org.apache.maven.artifact.Artifact.SCOPE_TEST;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.owasp.dependencycheck.maven.ArtifactScopeExcludedTest.ArtifactScopeExcludedTestBuilder.pluginDefaults;

class ArtifactScopeExcludedTest {

	static Collection<Object[]> getParameters() {
		return Arrays.asList(new Object[][]{
				{pluginDefaults().withTestString(SCOPE_COMPILE).withExpectedResult(false)},
				{pluginDefaults().withTestString(SCOPE_COMPILE_PLUS_RUNTIME).withExpectedResult(false)},
				{pluginDefaults().withTestString(SCOPE_TEST).withExpectedResult(true)},
				{pluginDefaults().withTestString(SCOPE_RUNTIME).withExpectedResult(false)},
				{pluginDefaults().withTestString(SCOPE_RUNTIME_PLUS_SYSTEM).withExpectedResult(false)},
				{pluginDefaults().withTestString(SCOPE_PROVIDED).withExpectedResult(false)},
				{pluginDefaults().withTestString(SCOPE_SYSTEM).withExpectedResult(false)},
				{pluginDefaults().withTestString(SCOPE_IMPORT).withExpectedResult(false)},

				// Runtime scope was having some issues... let's fix.
				{pluginDefaults().withSkipRuntimeScope(true).withTestString(SCOPE_COMPILE).withExpectedResult(false)},
				{pluginDefaults().withSkipRuntimeScope(true).withTestString(SCOPE_RUNTIME).withExpectedResult(true)},
		});
	}

    @ParameterizedTest(name = "{0}")
	@MethodSource("getParameters")
    void shouldExcludeArtifact(final ArtifactScopeExcludedTestBuilder builder) {
		final Filter<String> artifactScopeExcluded = new ArtifactScopeExcluded(
				builder.skipTestScope, builder.skipProvidedScope, builder.skipSystemScope, builder.skipRuntimeScope);
		assertThat(builder.expectedResult, is(equalTo(artifactScopeExcluded.passes(builder.testString))));
	}

	public static final class ArtifactScopeExcludedTestBuilder {

		private boolean skipTestScope;
		private boolean skipProvidedScope;
		private boolean skipSystemScope;
		private boolean skipRuntimeScope;
		private String testString;
		private boolean expectedResult;

		private ArtifactScopeExcludedTestBuilder() {
		}

		public static ArtifactScopeExcludedTestBuilder pluginDefaults() {
			return new ArtifactScopeExcludedTestBuilder()
					.withSkipTestScope(true)
					.withSkipProvidedScope(false)
					.withSkipRuntimeScope(false)
					.withSkipSystemScope(false);
		}

		public ArtifactScopeExcludedTestBuilder withSkipTestScope(final boolean skipTestScope) {
			this.skipTestScope = skipTestScope;
			return this;
		}

		public ArtifactScopeExcludedTestBuilder withSkipProvidedScope(final boolean skipProvidedScope) {
			this.skipProvidedScope = skipProvidedScope;
			return this;
		}

		public ArtifactScopeExcludedTestBuilder withSkipSystemScope(final boolean skipSystemScope) {
			this.skipSystemScope = skipSystemScope;
			return this;
		}

		public ArtifactScopeExcludedTestBuilder withSkipRuntimeScope(final boolean skipRuntimeScope) {
			this.skipRuntimeScope = skipRuntimeScope;
			return this;
		}

		public ArtifactScopeExcludedTestBuilder withTestString(final String testString) {
			this.testString = testString;
			return this;
		}

		public ArtifactScopeExcludedTestBuilder withExpectedResult(final boolean expectedResult) {
			this.expectedResult = expectedResult;
			return this;
		}

		@Override
		public String toString() {
			return String.format("new ArtifactScopeExcluded(%s, %s, %s, %s).passes(\"%s\") == %s;",
					skipTestScope, skipProvidedScope, skipSystemScope, skipRuntimeScope, testString, expectedResult);
		}
	}
}
