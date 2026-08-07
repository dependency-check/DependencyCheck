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
 */
package org.owasp.dependencycheck;

import org.owasp.dependencycheck.data.update.CachedWebDataSource;
import org.owasp.dependencycheck.data.update.exception.UpdateException;

/**
 * Test data source that always fails its update.
 */
public class FailingCachedWebDataSource implements CachedWebDataSource {

    @Override
    public boolean update(Engine engine) throws UpdateException {
        throw new UpdateException("Test update failure");
    }

    @Override
    public boolean purge(Engine engine) {
        return true;
    }
}
