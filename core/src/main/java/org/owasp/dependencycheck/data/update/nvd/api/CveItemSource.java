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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.nvd.api;

import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;

import java.io.IOException;

public interface CveItemSource<T extends DefCveItem> extends AutoCloseable {

    /**
     * Returns whether there is another item.
     *
     * @return <code>true</code> if there is another item; otherwise
     * <code>false</code>.
     */
    boolean hasNext();

    /**
     * Returns the next item.
     *
     * @return the next item
     * @throws IOException thrown if there is an error reading from the source
     */
    T next() throws IOException;
}
