package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.io.WritingSerializer;
import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.io.Writer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.Jwk;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public final class JwksBridge {

    private JwksBridge() {
    }

    @SuppressWarnings({"unchecked", "unused"}) // used via reflection by io.jsonwebtoken.security.Jwks
    public static String UNSAFE_JSON(Jwk<?> jwk) {
        Writer<Jwk<?>> writer = Services.loadFirst(Writer.class);
        Assert.stateNotNull(writer, "Writer lookup failed. Ensure JSON impl .jar is in the runtime classpath.");
        WritingSerializer<Jwk<?>> ser = new WritingSerializer<>(writer, "JWK");
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        OutputStreamWriter w = new OutputStreamWriter(baos, StandardCharsets.UTF_8);
        try {
            ser.accept(w, jwk);
        } finally {
            Objects.nullSafeClose(w);
        }
        return Strings.utf8(baos.toByteArray());
    }
}
