package org.owasp.dependencycheck.utils.json;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.impl.classic.AbstractHttpClientResponseHandler;
import org.apache.hc.core5.http.HttpEntity;

import java.io.IOException;
import java.io.InputStream;

public class ToJsonResponseHandler extends AbstractHttpClientResponseHandler<CentralSearchResponse> {
    private static final ObjectMapper MAPPER = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);

    @Override
    public CentralSearchResponse handleEntity(HttpEntity entity) throws IOException {
        try (InputStream in = entity.getContent()) {
            return MAPPER.readValue(in, CentralSearchResponse.class);
        } catch (IOException e) {
            final String errorMessage = "Failed to parse JSON Response: " + e.getMessage();
            throw new IOException(errorMessage, e);
        }
    }
}
