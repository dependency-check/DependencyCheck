/*
 * Copyright 2014 OWASP.
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
package org.owasp.dependencycheck.data.update;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;
import java.util.Properties;

import mockit.Mock;
import mockit.MockUp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.DependencyVersion;

/**
 * @author Jeremy Long
 */
public class EngineVersionCheckTest extends BaseTest {

    @Mock
    private CveDB cveDb;
    @InjectMocks
    private DatabaseProperties dbProperties;

    /**
     * Test of shouldUpdate method, of class EngineVersionCheck.
     */
    @Test
    public void testShouldUpdate() throws Exception {
        new MockUp<DatabaseProperties>() {
            private final Properties properties = new Properties();

            @Mock
            public void $init(CveDB db) {
                //empty
            }

            @Mock
            public void save(String key, String value) throws UpdateException {
                properties.setProperty(key, value);
            }

            @Mock
            public String getProperty(String key) {
                return properties.getProperty(key);
            }
        };

        String updateToVersion = "1.2.6";
        String currentVersion = "1.2.6";

        long lastChecked = dateToSeconds("2014-12-01");
        long now = dateToSeconds("2014-12-01");

        EngineVersionCheck instance = new EngineVersionCheck(getSettings());
        boolean expResult = false;
        instance.setUpdateToVersion(updateToVersion);
        boolean result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "1.2.5";
        currentVersion = "1.2.5";
        lastChecked = dateToSeconds("2014-10-01");
        now = dateToSeconds("2014-12-01");
        expResult = true;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);
        //System.out.println(properties.getProperty(CURRENT_ENGINE_RELEASE));

        updateToVersion = "1.2.5";
        currentVersion = "1.2.5";
        lastChecked = dateToSeconds("2014-12-01");
        now = dateToSeconds("2014-12-03");
        expResult = false;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "1.2.6";
        currentVersion = "1.2.5";
        lastChecked = dateToSeconds("2014-12-01");
        now = dateToSeconds("2014-12-03");
        expResult = true;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "1.2.5";
        currentVersion = "1.2.6";
        lastChecked = dateToSeconds("2014-12-01");
        now = dateToSeconds("2014-12-08");
        expResult = false;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "";
        currentVersion = "1.2.5";
        lastChecked = dateToSeconds("2014-12-01");
        now = dateToSeconds("2014-12-03");
        expResult = false;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "";
        currentVersion = "1.2.5";
        lastChecked = dateToSeconds("2014-12-01");
        now = dateToSeconds("2015-12-08");
        expResult = true;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, dbProperties, currentVersion);
        assertEquals(expResult, result);
    }

    /**
     * Test of getCurrentReleaseVersion method, of class EngineVersionCheck.
     */
    @Test
    public void testGetCurrentReleaseVersion() {
        EngineVersionCheck instance = new EngineVersionCheck(getSettings());
        DependencyVersion minExpResult = new DependencyVersion("1.2.6");
        String release = instance.getCurrentReleaseVersion();
        DependencyVersion result = new DependencyVersion(release);
        assertTrue(minExpResult.compareTo(result) <= 0);
    }

    /**
     * Converts a date in the form of yyyy-MM-dd into the epoch milliseconds.
     *
     * @param date a date in the format of yyyy-MM-dd
     * @return seconds
     */
    private long dateToSeconds(String date) {
        TemporalAccessor ta = DateTimeFormatter.ISO_LOCAL_DATE.parse(date);
        return LocalDate.from(ta).atStartOfDay(ZoneId.systemDefault()).toEpochSecond();
    }

}
