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
package org.owasp.dependencycheck.utils;

import org.junit.jupiter.api.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.exception.ParseException;

import java.time.ZonedDateTime;
import java.util.Calendar;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 * @author Jeremy Long
 */
class DateUtilTest extends BaseTest {

    /**
     * Test of withinDateRange method, of class DateUtil.
     */
    @Test
    void testWithinDateRange() {
        Calendar c = Calendar.getInstance();

        long current = c.getTimeInMillis() / 1000;
        long lastRun = current - (3 * (60 * 60 * 24));
        int range = 7; // 7 days
        boolean expResult = true;
        boolean result = DateUtil.withinDateRange(lastRun, current, range);
        assertEquals(expResult, result);

        lastRun = c.getTimeInMillis() / 1000 - (8 * (60 * 60 * 24));
        expResult = false;
        result = DateUtil.withinDateRange(lastRun, current, range);
        assertEquals(expResult, result);
    }

    /**
     * Test of withinDateRange method, of class DateUtil.
     */
    @Test
    void testWithinZonedDateRange() {
        ZonedDateTime lastRun = ZonedDateTime.parse("2023-11-15T11:15:03Z");
        ZonedDateTime current = ZonedDateTime.parse("2023-11-17T11:15:03Z");
        int range = 5;
        boolean expResult = true;
        boolean result = DateUtil.withinDateRange(lastRun, current, range);
        assertEquals(expResult, result);

        current = ZonedDateTime.parse("2023-11-21T11:15:03Z");
        expResult = false;
        result = DateUtil.withinDateRange(lastRun, current, range);
        assertEquals(expResult, result);
    }

    /**
     * Test of parseXmlDate method, of class DateUtil.
     *
     * @throws ParseException thrown when there is a parse error
     */
    @Test
    void testParseXmlDate() throws ParseException {
        String xsDate = "2019-01-02Z";
        Calendar result = DateUtil.parseXmlDate(xsDate);
        assertEquals(2019, result.get(Calendar.YEAR));
        //month is zero based.
        assertEquals(0, result.get(Calendar.MONTH));
        assertEquals(2, result.get(Calendar.DATE));
    }

    @Test
    void testGetEpochValueInSeconds() {
        String milliseconds = "1550538553466";
        long expected = 1550538553;
        long result = DateUtil.getEpochValueInSeconds(milliseconds);
        assertEquals(expected, result);

        milliseconds = "blahblahblah";
        expected = 0;
        result = DateUtil.getEpochValueInSeconds(milliseconds);
        assertEquals(expected, result);

        milliseconds = "1550538553";
        expected = 1550538553;
        result = DateUtil.getEpochValueInSeconds(milliseconds);
        assertEquals(expected, result);
    }

}
