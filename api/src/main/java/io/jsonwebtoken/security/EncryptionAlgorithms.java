package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Maps;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

/**
 * @since JJWT_RELEASE_VERSION
 */
public final class EncryptionAlgorithms {

    //prevent instantiation
    private EncryptionAlgorithms() {
    }

    private static final String HMAC = "io.jsonwebtoken.impl.security.HmacAesAeadAlgorithm";
    private static final String GCM = "io.jsonwebtoken.impl.security.GcmAesAeadAlgorithm";
    private static final Class<?>[] CTOR_ARG_TYPES = new Class[]{int.class};

    private static SymmetricAeadAlgorithm alg(String fqcn, int keyLength) {
        return Classes.newInstance(fqcn, CTOR_ARG_TYPES, keyLength);
    }

    /**
     * AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.3">RFC 7518, Section 5.2.3</a>.  This algorithm
     * requires a 256 bit (32 byte) key.
     */
    public static final SymmetricAeadAlgorithm A128CBC_HS256 = alg(HMAC, 128);

    /**
     * AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.4">RFC 7518, Section 5.2.4</a>. This algorithm
     * requires a 384 bit (48 byte) key.
     */
    public static final SymmetricAeadAlgorithm A192CBC_HS384 = alg(HMAC, 192);

    /**
     * AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.5">RFC 7518, Section 5.2.5</a>.  This algorithm
     * requires a 512 bit (64 byte) key.
     */
    public static final SymmetricAeadAlgorithm A256CBC_HS512 = alg(HMAC, 256);

    /**
     * &quot;AES GCM using 128-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a>.  This algorithm requires
     * a 128 bit (16 byte) key.
     */
    public static final SymmetricAeadAlgorithm A128GCM = alg(GCM, 128);

    /**
     * &quot;AES GCM using 192-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a>.  This algorithm requires
     * a 192 bit (24 byte) key.
     */
    public static final SymmetricAeadAlgorithm A192GCM = alg(GCM, 192);

    /**
     * &quot;AES GCM using 256-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a>.  This algorithm requires
     * a 256 bit (32 byte) key.
     */
    public static final SymmetricAeadAlgorithm A256GCM = alg(GCM, 256);

    private static final Map<String, SymmetricAeadAlgorithm> SYMMETRIC_VALUES_BY_NAME = Collections.unmodifiableMap(Maps
        .of(A128CBC_HS256.getId(), A128CBC_HS256)
        .and(A192CBC_HS384.getId(), A192CBC_HS384)
        .and(A256CBC_HS512.getId(), A256CBC_HS512)
        .and(A128GCM.getId(), A128GCM)
        .and(A192GCM.getId(), A192GCM)
        .and(A256GCM.getId(), A256GCM)
        .build());

    public static SymmetricAeadAlgorithm forName(String name) {
        Assert.hasText(name, "name cannot be null or empty.");
        SymmetricAeadAlgorithm alg = SYMMETRIC_VALUES_BY_NAME.get(name.toUpperCase());
        if (alg == null) {
            String msg = "'" + name + "' is not a JWE specification standard name.  The standard names are: " +
            Strings.collectionToCommaDelimitedString(SYMMETRIC_VALUES_BY_NAME.keySet());
            throw new IllegalArgumentException(msg);
        }
        return alg;
    }

    public static Collection<SymmetricAeadAlgorithm> values() {
        return SYMMETRIC_VALUES_BY_NAME.values();
    }
}
