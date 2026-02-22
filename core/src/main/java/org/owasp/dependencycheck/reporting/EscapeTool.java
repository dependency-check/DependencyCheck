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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.reporting;

import java.net.URLEncoder;
import java.util.Set;
import javax.annotation.concurrent.ThreadSafe;
import static java.nio.charset.StandardCharsets.UTF_8;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.dependencycheck.dependency.naming.Identifier;

/**
 * An extremely simple wrapper around various escape utils to perform URL and
 * HTML encoding within the reports. This class was created to simplify the
 * velocity configuration and avoid using the "built-in" escape tool.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class EscapeTool {
    /**
     * URL Encodes the provided text.
     *
     * @param text the text to encode
     * @return the URL encoded text
     */
    public String url(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        return URLEncoder.encode(text, UTF_8);
    }

    /**
     * HTML Encodes the provided text.
     *
     * @param text the text to encode
     * @return the HTML encoded text
     */
    public String html(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        return StringEscapeUtils.escapeHtml4(text);
    }

    public String html(Object o) {
        return xml(o == null ? null : o.toString());
    }

    /**
     * XML Encodes the provided text.
     *
     * @param text the text to encode
     * @return the XML encoded text
     */
    public String xml(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        return StringEscapeUtils.escapeXml11(text);
    }

    public String xml(Object o) {
        return xml(o == null ? null : o.toString());
    }

    /**
     * JSON Encodes the provided text.
     *
     * @param text the text to encode
     * @return the JSON encoded text
     */
    public String json(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        return StringEscapeUtils.escapeJson(text);
    }

    public String json(Object o) {
        return xml(o == null ? null : o.toString());
    }

    /**
     * JavaScript encodes the provided text.
     *
     * @param text the text to encode
     * @return the JavaScript encoded text
     */
    public String javascript(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        return StringEscapeUtils.escapeEcmaScript(text);
    }

    /**
     * Formats text for CSV format. This includes trimming whitespace, replace
     * line breaks with spaces, and if necessary quotes the text and/or escapes
     * contained quotes.
     *
     * @param text the text to escape and quote
     * @return the escaped and quoted text
     */
    public String csv(String text) {
        if (text == null || text.isEmpty()) {
            return "\"\"";
        }
        final String str = text.trim().replace("\n", " ");
        if (str.isBlank()) {
            return "\"\"";
        }
        return StringEscapeUtils.escapeCsv(str);
    }

    /**
     * Takes a set of Identifiers, filters them to none CPE, and formats them
     * for display in a CSV.
     *
     * @param ids the set of identifiers
     * @return the formatted list of none CPE identifiers
     */
    public String csvIdentifiers(Set<Identifier> ids) {
        if (ids == null || ids.isEmpty()) {
            return "\"\"";
        }
        boolean addComma = false;
        final StringBuilder sb = new StringBuilder();
        for (Identifier id : ids) {
            if (addComma) {
                sb.append(", ");
            } else {
                addComma = true;
            }
            sb.append(id.getValue());
        }
        if (sb.length() == 0) {
            return "\"\"";
        }
        return StringEscapeUtils.escapeCsv(sb.toString());
    }

    /**
     * Takes a set of Identifiers, filters them to just CPEs, and formats them
     * for confidence display in a CSV.
     *
     * @param ids the set of identifiers
     * @return the formatted list of confidence
     */
    public String csvCpeConfidence(Set<Identifier> ids) {
        if (ids == null || ids.isEmpty()) {
            return "\"\"";
        }
        boolean addComma = false;
        final StringBuilder sb = new StringBuilder();
        for (Identifier id : ids) {
            if (addComma) {
                sb.append(", ");
            } else {
                addComma = true;
            }
            sb.append(id.getConfidence());
        }
        if (sb.length() == 0) {
            return "\"\"";
        }
        return StringEscapeUtils.escapeCsv(sb.toString());
    }
}
