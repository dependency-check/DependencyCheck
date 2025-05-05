/*
 * Copyright 2015 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.data.nvdcve;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseDBTestCase;

import java.sql.Connection;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 *
 * @author jeremy long
 */
class DatabaseManagerTest extends BaseDBTestCase {

    /**
     * Test of initialize method, of class DatabaseManager.
     *
     * @throws org.owasp.dependencycheck.data.nvdcve.DatabaseException
     */
    @Test
    void testInitialize() throws DatabaseException, SQLException {
        DatabaseManager factory = new DatabaseManager(getSettings());
        factory.open();
        try (Connection result = factory.getConnection()) {
            assertNotNull(result);
        }
        factory.close();
        factory.cleanup();
    }
}
