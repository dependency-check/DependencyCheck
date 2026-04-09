package org.owasp.dependencycheck.utils.json;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CentralSearchResponse {
    @JsonProperty("response")
    private CentralSearchResponseContent body;

    public CentralSearchResponseContent getBody() {
        return body;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CentralSearchResponseContent {
        @JsonProperty
        private int numFound;
        @JsonProperty
        private List<ResponseDocument> docs;

        public int getNumFound() {
            return numFound;
        }

        public List<ResponseDocument> getDocs() {
            return docs;
        }
    }
}
