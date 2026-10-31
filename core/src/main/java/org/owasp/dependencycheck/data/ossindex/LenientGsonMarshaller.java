package org.owasp.dependencycheck.data.ossindex;

import com.google.common.reflect.TypeToken;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonIOException;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.TypeAdapter;
import com.google.gson.internal.bind.TypeAdapters;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import org.sonatype.goodies.packageurl.PackageUrl;
import org.sonatype.ossindex.service.client.marshal.Marshaller;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.lang.reflect.Type;
import java.net.URI;

/**
 * Unmarshaller which will unmarshal nulls for any URIs which are not strictly valid.
 */
class LenientGsonMarshaller implements Marshaller {
    private final Gson lenientGson;

    public LenientGsonMarshaller() {
        lenientGson = new GsonBuilder()
                .registerTypeAdapter(PackageUrl.class, new PackageUrlAdapter())
                .registerTypeAdapter(URI.class, new LenientUriAdapter())
                .create();
    }

    @Override
    public String marshal(final Object value) throws IOException {
        try {
            return lenientGson.toJson(value);
        } catch (JsonParseException e) {
            throw new IOException(e);
        }
    }

    @Override
    public void marshal(final Object value, final Writer writer) throws IOException {
        try {
            lenientGson.toJson(value, writer);
            writer.flush();
        } catch (JsonParseException e) {
            throw new IOException(e);
        }
    }

    @Override
    public <T> T unmarshal(String value, Class<T> type) throws IOException {
        try {
            return lenientGson.fromJson(value, type);
        } catch (JsonParseException e) {
            throw new IOException(e);
        }
    }

    @Override
    public <T> T unmarshal(Reader reader, Class<T> type) throws IOException {
        try {
            return lenientGson.fromJson(reader, type);
        } catch (JsonParseException e) {
            throw new IOException(e);
        }
    }

    @Override
    public <T> T unmarshal(String value, TypeToken<T> type) throws IOException {
        try {
            return lenientGson.fromJson(value, type.getType());
        } catch (JsonParseException e) {
            throw new IOException(e);
        }
    }

    @Override
    public <T> T unmarshal(Reader reader, TypeToken<T> type) throws IOException {
        try {
            return lenientGson.fromJson(reader, type.getType());
        } catch (JsonParseException e) {
            throw new IOException(e);
        }
    }

    private static class PackageUrlAdapter implements JsonDeserializer<PackageUrl>, JsonSerializer<PackageUrl> {
        @Override
        public PackageUrl deserialize(final JsonElement element, final Type type, final JsonDeserializationContext context) {
            return PackageUrl.parse(element.getAsString());
        }

        @Override
        public JsonElement serialize(final PackageUrl value, final Type type, final JsonSerializationContext context) {
            return new JsonPrimitive(value.toString());
        }
    }

    private static class LenientUriAdapter extends TypeAdapter<URI> {
        @Override
        public URI read(JsonReader in) throws IOException {
            try {
                return TypeAdapters.URI.read(in);
            } catch (JsonIOException e) {
                return null;
            }
        }

        @Override
        public void write(JsonWriter out, URI value) throws IOException {
            TypeAdapters.URI.write(out, value);
        }
    }
}
