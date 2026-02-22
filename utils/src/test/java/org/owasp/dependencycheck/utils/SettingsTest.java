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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Jeremy Long
 */
class SettingsTest extends BaseTest {

    /**
     * Test of getString method, of class Settings.
     */
    @Test
    void testGetString() {
        String key = Settings.KEYS.NVD_API_DATAFEED_VALID_FOR_DAYS;
        String expResult = "7";
        String result = getSettings().getString(key);
        assertTrue(result.endsWith(expResult));
    }

    /**
     * Test of getDataFile method, of class Settings.
     */
    @Test
    void testGetDataFile() {
        String key = Settings.KEYS.DATA_DIRECTORY;
        String expResult = "data";
        File result = getSettings().getDataFile(key);
        assertTrue(result.getAbsolutePath().endsWith(expResult));
    }

    /**
     * Test of mergeProperties method, of class Settings.
     *
     * @throws java.io.IOException thrown when the test fails
     * @throws java.net.URISyntaxException thrown when the test fails
     */
    @Test
    void testMergeProperties_String() throws IOException, URISyntaxException {
        String key = Settings.KEYS.PROXY_PORT;
        String expResult = getSettings().getString(key);
        File f = new File(this.getClass().getClassLoader().getResource("test.properties").toURI());
        //InputStream in = this.getClass().getClassLoader().getResourceAsStream("test.properties");
        getSettings().mergeProperties(f.getAbsolutePath());
        String result = getSettings().getString(key);
        assertTrue((expResult == null && result != null) || !expResult.equals(result), "setting didn't change?");
    }

    /**
     * Test of setString method, of class Settings.
     */
    @Test
    void testSetString() {
        String key = "newProperty";
        String value = "someValue";
        getSettings().setString(key, value);
        String expResults = getSettings().getString(key);
        assertEquals(value, expResults);
    }

    /**
     * Test of setStringIfNotNull method, of class Settings.
     */
    @Test
    void testSetStringIfNotNull() {
        String key = "nullableProperty";
        String value = "someValue";
        getSettings().setString(key, value);
        getSettings().setStringIfNotNull(key, null); // NO-OP
        String expResults = getSettings().getString(key);
        assertEquals(value, expResults);
    }

    /**
     * Test of setStringIfNotNull method, of class Settings.
     */
    @Test
    void testSetStringIfNotEmpty() {
        String key = "optionalProperty";
        String value = "someValue";
        getSettings().setString(key, value);
        getSettings().setStringIfNotEmpty(key, ""); // NO-OP
        String expResults = getSettings().getString(key);
        assertEquals(value, expResults);
    }

    /**
     * Test of getString method, of class Settings.
     */
    @Test
    void testGetString_String_String() {
        String key = "key That Doesn't Exist";
        String defaultValue = "blue bunny";
        String expResult = "blue bunny";
        String result = getSettings().getString(key);
        assertNull(result);
        result = getSettings().getString(key, defaultValue);
        assertEquals(expResult, result);
    }

    /**
     * Test of getString method, of class Settings.
     */
    @Test
    void testGetString_String() {
        String key = Settings.KEYS.CONNECTION_TIMEOUT;
        String result = getSettings().getString(key);
        assertNull(result);
    }

    /**
     * Test of getInt method, of class Settings.
     */
    @Test
    void testGetInt() throws InvalidSettingException {
        String key = "SomeNumber";
        int expResult = 85;
        getSettings().setString(key, "85");
        int result = getSettings().getInt(key);
        assertEquals(expResult, result);
    }

    /**
     * Test of getInt method, of class Settings.
     */
    @Test
    void testGetIntDefault() {
        String key = "SomeKey";
        int expResult = 85;
        getSettings().setString(key, "blue");
        int result = getSettings().getInt(key, expResult);
        assertEquals(expResult, result);
    }

    /**
     * Test of getLong method, of class Settings.
     */
    @Test
    void testGetLong() throws InvalidSettingException {
        String key = "SomeNumber";
        long expResult = 300L;
        getSettings().setString(key, "300");
        long result = getSettings().getLong(key);
        assertEquals(expResult, result);
    }

    /**
     * Test of getBoolean method, of class Settings.
     */
    @Test
    void testGetBoolean() throws InvalidSettingException {
        String key = "SomeBoolean";
        getSettings().setString(key, "false");
        boolean expResult = false;
        boolean result = getSettings().getBoolean(key);
        assertEquals(expResult, result);

        key = "something that does not exist";
        expResult = true;
        result = getSettings().getBoolean(key, true);
        assertEquals(expResult, result);
    }

    /**
     * Test of removeProperty method, of class Settings.
     */
    @Test
    void testRemoveProperty() {
        String key = "SomeKey";
        String value = "value";
        String dfault = "default";
        getSettings().setString(key, value);
        String ret = getSettings().getString(key);
        assertEquals(value, ret);
        getSettings().removeProperty(key);
        ret = getSettings().getString(key, dfault);
        assertEquals(dfault, ret);
    }

    /**
     * Test of getConnectionString.
     */
    @Test
    void testGetConnectionString() throws Exception {
        String value = getSettings().getConnectionString(Settings.KEYS.DB_CONNECTION_STRING, Settings.KEYS.DB_FILE_NAME);
        assertNotNull(value);
        String msg = null;
        try {
            value = getSettings().getConnectionString("invalidKey", null);
        } catch (InvalidSettingException e) {
            msg = e.getMessage();
        }
        assertNotNull(msg);
    }

    /**
     * Test of getTempDirectory.
     */
    @Test
    void testGetTempDirectory() throws Exception {
        File tmp = getSettings().getTempDirectory();
        assertTrue(tmp.exists());
    }

    /**
     * Assert {@link Settings#getArray(String)} from a delimited string returns
     * multiple values in an array.
     */
    @Test
    void testGetArrayFromADelimitedString() {
        // GIVEN a delimited string
        final String delimitedString = "value1,value2";
        getSettings().setString("key", delimitedString);

        // WHEN getting the array
        final String[] array = getSettings().getArray("key");

        // THEN the split array is returned
        assertThat("Expected the array to be non-null", array, notNullValue());
        assertThat("Expected the array to have two values", array.length, is(2));
        assertThat("Expected the first array value to be value1", array[0], is("value1"));
        assertThat("Expected the second array value to be value2", array[1], is("value2"));
    }

    /**
     * Assert {@link Settings#getArray(String)} returns {@code null} if the
     * property is not set.
     */
    @Test
    void testGetArrayWhereThePropertyIsNotSet() {
        // WHEN getting the array
        final String[] array = getSettings().getArray("key");

        // THEN null is returned
        assertThat("Expected the array to be null", array, nullValue());
    }

    /**
     * Assert {@link Settings#setArrayIfNotEmpty(String, String[])} with an
     * empty array is ignored.
     */
    @Test
    void testSetArrayNotEmptyIgnoresAnEmptyArray() {
        // GIVEN an empty array
        final String[] array = {};

        // WHEN setting the array
        getSettings().setArrayIfNotEmpty("key", array);

        // THEN the property was not set
        assertThat("Expected the property to not be set", getSettings().getString("key"), nullValue());
    }

    /**
     * Assert {@link Settings#setArrayIfNotEmpty(String, String[])} with a null
     * array is ignored.
     */
    @Test
    void testSetArrayNotEmptyIgnoresAnNullArray() {
        // GIVEN a null array
        final String[] array = null;

        // WHEN setting the array
        getSettings().setArrayIfNotEmpty("key", array);

        // THEN the property was not set
        assertThat("Expected the property to not be set", getSettings().getString("key"), nullValue());
    }

    /**
     * Assert {@link Settings#setArrayIfNotEmpty(String, List<String>)}
     * correctly stores the list as an array.
     */
    @Test
    void testSetArrayNotEmptyWithList() {
        // GIVEN a null array
        final List<String> list = new ArrayList<>();
        list.add("one");
        list.add("two");

        // WHEN setting the array
        getSettings().setArrayIfNotEmpty("key", list);

        // THEN the property was not set
        assertThat("Expected the property to not be set", getSettings().getArray("key"),
                equalTo(new String[]{"one", "two"}));
    }

    @Test
    void testMaskedKeys() {
        getSettings().initMaskedKeys();
        assertThat("password should be masked",
                getSettings().getPrintableValue("odc.database.password", "s3Cr3t!"),
                equalTo("********"));

        assertThat("tokens should be masked",
                getSettings().getPrintableValue("odc.api.token", "asf4b$3428vasd84$#$45asda"),
                equalTo("********"));

        assertThat("other keys should not be masked",
                getSettings().getPrintableValue("odc.version", "5.0.0"),
                equalTo("5.0.0"));
    }
}
