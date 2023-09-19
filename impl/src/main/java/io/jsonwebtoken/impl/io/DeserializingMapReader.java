package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.io.Reader;
import io.jsonwebtoken.lang.Assert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class DeserializingMapReader implements Reader<Map<String, ?>> {

    private final Deserializer<Map<String, ?>> deserializer;

    public DeserializingMapReader(Deserializer<Map<String, ?>> deserializer) {
        this.deserializer = Assert.notNull(deserializer, "Deserializer cannot be null.");
    }

    @Override
    public Map<String, ?> read(java.io.Reader in) throws IOException {
        int len = 256;
        ByteArrayOutputStream baos = new ByteArrayOutputStream(len);
        try (OutputStreamWriter writer = new OutputStreamWriter(baos, StandardCharsets.UTF_8)) {
            char[] buf = new char[len];
            while (len != -1) {
                len = in.read(buf, 0, buf.length);
                if (len > 0) writer.write(buf, 0, len);
            }
        }
        byte[] data = baos.toByteArray();
        return deserializer.deserialize(data);
    }
}
