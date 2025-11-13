/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.owasp.dependencycheck.utils.scarf;

import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.Settings;

import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;


/**
 * A utility class to collect and send telemetry data to scarf.
 * <p>
 * Originally from https://github.com/apache/sedona/blob/4e4791d08ddafcf0b46c3d2c092f750eb5dcf2ef/common/src/main/java/org/apache/sedona/common/utils/TelemetryCollector.java#L26
 */
public class TelemetryCollector {

    private static final String BASE_URL = "https://dependency-check.gateway.scarf.sh/scan/";
    private static final AtomicBoolean telemetrySubmitted = new AtomicBoolean(false);

    public static void send(Settings settings) {
        try {
            String tool = settings.getString(Settings.KEYS.APPLICATION_NAME, "dependency-check");
            String version = settings.getString(Settings.KEYS.APPLICATION_VERSION, "Unknown");
            send(settings, tool, version);
        } catch (Exception e) {
            // Silent catch block
        }
    }
    public static void send(Settings settings, String tool, String version) {
        if (!telemetrySubmitted.compareAndSet(false, true)) {
            return;
        }
        // Check for user opt-out
        if (System.getenv("SCARF_NO_ANALYTICS") != null
                && System.getenv("SCARF_NO_ANALYTICS").equalsIgnoreCase("true")
                || System.getenv("DO_NOT_TRACK") != null
                && System.getenv("DO_NOT_TRACK").equalsIgnoreCase("true")
                || System.getProperty("SCARF_NO_ANALYTICS") != null
                && System.getProperty("SCARF_NO_ANALYTICS").equalsIgnoreCase("true")
                || System.getProperty("DO_NOT_TRACK") != null
                && System.getProperty("DO_NOT_TRACK").equalsIgnoreCase("true")) {
            return;
        }
        try {
            URL telemetryUrl = new URL(BASE_URL
                    + URLEncoder.encode(tool, StandardCharsets.UTF_8)
                    + "/"
                    + URLEncoder.encode(version, StandardCharsets.UTF_8));
            Thread telemetryThread = createThread(settings, telemetryUrl);
            telemetryThread.start();
        } catch (Exception e) {
            // Silent catch block
        }
    }

    private static Thread createThread(Settings settings, URL url) {
        Thread telemetryThread =
                new Thread("telemetry-thread") {
                    @Override
                    public void run() {
                        try {
                            Downloader downloader = Downloader.getInstance();
                            downloader.configure(settings);
                            downloader.fetchContent(url, StandardCharsets.UTF_8);
                        } catch (Exception e) {
                            // Silent catch block
                        }
                    }
                };
        telemetryThread.setDaemon(true);
        return telemetryThread;
    }
}