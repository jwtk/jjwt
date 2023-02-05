package io.jsonwebtoken.impl.lang;

import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

public final class Fields {

    private Fields() { // prevent instantiation
    }

    public static Field<String> string(String id, String name) {
        return builder(String.class).setId(id).setName(name).build();
    }

    public static Field<Date> rfcDate(String id, String name) {
        return builder(Date.class).setConverter(JwtDateConverter.INSTANCE).setId(id).setName(name).build();
    }

    public static Field<List<X509Certificate>> x509Chain(String id, String name) {
        return builder(X509Certificate.class)
                .setConverter(Converters.X509_CERTIFICATE).list()
                .setId(id).setName(name).build();
    }

    public static <T> FieldBuilder<T> builder(Class<T> type) {
        return new DefaultFieldBuilder<>(type);
    }

    public static Field<Set<String>> stringSet(String id, String name) {
        return builder(String.class).set().setId(id).setName(name).build();
    }

    public static Field<URI> uri(String id, String name) {
        return builder(URI.class).setConverter(Converters.URI).setId(id).setName(name).build();
    }

    public static FieldBuilder<byte[]> bytes(String id, String name) {
        return builder(byte[].class).setConverter(Converters.BASE64URL_BYTES).setId(id).setName(name);
    }

    public static FieldBuilder<BigInteger> bigInt(String id, String name) {
        return builder(BigInteger.class).setConverter(Converters.BIGINT).setId(id).setName(name);
    }

    public static Field<BigInteger> secretBigInt(String id, String name) {
        return bigInt(id, name).setSecret(true).build();
    }
}
