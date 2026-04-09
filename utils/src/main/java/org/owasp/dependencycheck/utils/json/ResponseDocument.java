package org.owasp.dependencycheck.utils.json;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Encapsulates an individual response document from Central search when using JSON responses.
 * <br/>
 * NOTE: The actual document format has more properties than are enumerated here, but the central analyzer does not use them.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ResponseDocument {
    @JsonProperty
    private String id;
    @JsonProperty("g")
    private String groupId;
    @JsonProperty("a")
    private String artifactId;
    @JsonProperty("v")
    private String version;
    @JsonProperty("ec")
    private List<String> attributes;

    public String getId() {
        return id;
    }

    public String getArtifactId() {
        return artifactId;
    }

    public String getGroupId() {
        return groupId;
    }

    public List<String> getAttributes() {
        return attributes;
    }

    public String getVersion() {
        return version;
    }
}
