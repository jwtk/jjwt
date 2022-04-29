package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.impl.io.Codec;
import io.jsonwebtoken.impl.security.JwtX509StringConverter;

import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

public final class Converters {

    public static final Converter<URI, Object> URI = Converters.forEncoded(URI.class, new UriStringConverter());

    public static final Converter<byte[], Object> BASE64URL_BYTES = Converters.forEncoded(byte[].class, Codec.BASE64URL);

    public static final Converter<X509Certificate, Object> X509_CERTIFICATE =
        Converters.forEncoded(X509Certificate.class, new JwtX509StringConverter());

    public static final Converter<BigInteger, byte[]> BIGINT_UBYTES = new BigIntegerUBytesConverter();
    public static final Converter<BigInteger, Object> BIGINT = Converters.forEncoded(BigInteger.class,
        compound(BIGINT_UBYTES, Codec.BASE64URL));

    //prevent instantiation
    private Converters() {
    }

    public static <T> Converter<T, Object> forType(Class<T> clazz) {
        return new RequiredTypeConverter<>(clazz);
    }

    public static <T> Converter<Set<T>, Object> forSet(Converter<T, Object> elementConverter) {
        return CollectionConverter.forSet(elementConverter);
    }

    public static <T> Converter<List<T>, Object> forList(Converter<T, Object> elementConverter) {
        return CollectionConverter.forList(elementConverter);
    }

    public static <T> Converter<T, Object> forEncoded(Class<T> elementType, Converter<T, String> elementConverter) {
        return new EncodedObjectConverter<>(elementType, elementConverter);
    }

    public static <A, B, C> Converter<A, C> compound(final Converter<A, B> aConv, final Converter<B, C> bConv) {
        return new CompoundConverter<>(aConv, bConv);
    }
}