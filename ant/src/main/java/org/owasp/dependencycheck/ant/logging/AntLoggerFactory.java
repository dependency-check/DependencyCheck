/*
 * This file is part of dependency-check-ant.
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
 * Copyright (c) 2015 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.ant.logging;

import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;

/**
 * An implementation of {@link org.slf4j.ILoggerFactory} which always returns {@link AntLoggerAdapter} instances.
 *
 * @author colezlaw
 */
public class AntLoggerFactory implements ILoggerFactory {

    /**
     * Returns the Ant logger adapter.
     *
     * @param name the logger name
     * @return the Ant logger adapter
     */
    @Override
    public Logger getLogger(String name) {
        return new AntLoggerAdapter(name);
    }
}
