package org.owasp.dependencycheck.utils.json;

import com.fasterxml.jackson.annotation.JsonProperty;

public class HeaderParams {
    @JsonProperty("q")
    private String query;
    private String core;
    private boolean indent;
    @JsonProperty("fl")
    private String queriedFieldsList;
    private String start;
    private String sort;
    private int rows;
    private String responseType;
    private String version;

    public void setIndent(String value) {
        this.indent = "on".equals(value);
    }
}
