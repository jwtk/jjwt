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

    private static final Class MAC_CLASS = Classes.forName("io.jsonwebtoken.impl.security.MacSignatureAlgorithm");
    private static final String HMAC = "io.jsonwebtoken.impl.security.HmacAesEncryptionAlgorithm";
    private static final Class[] HMAC_ARGS = new Class[]{String.class, MAC_CLASS};

    private static final String GCM = "io.jsonwebtoken.impl.security.GcmAesEncryptionAlgorithm";
    private static final Class[] GCM_ARGS = new Class[]{String.class, int.class};

    private static AeadSymmetricEncryptionAlgorithm hmac(int keyLength) {
        int digestLength = keyLength * 2;
        String name = "A" + keyLength + "CBC-HS" + digestLength;
        SignatureAlgorithm macSigAlg = Classes.newInstance(SignatureAlgorithms.HMAC, SignatureAlgorithms.HMAC_ARGS, name, "HmacSHA" + digestLength, keyLength);
        return Classes.newInstance(HMAC, HMAC_ARGS, name, macSigAlg);
    }

    private static AeadSymmetricEncryptionAlgorithm gcm(int keyLength) {
        String name = "A" + keyLength + "GCM";
        return Classes.newInstance(GCM, GCM_ARGS, name, keyLength);
    }

    /**
     * AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.3">RFC 7518, Section 5.2.3</a>.  This algorithm
     * requires a 256 bit (32 byte) key.
     */
    public static final AeadSymmetricEncryptionAlgorithm A128CBC_HS256 = hmac(128);

    /**
     * AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.4">RFC 7518, Section 5.2.4</a>. This algorithm
     * requires a 384 bit (48 byte) key.
     */
    public static final AeadSymmetricEncryptionAlgorithm A192CBC_HS384 = hmac(192);

    /**
     * AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.5">RFC 7518, Section 5.2.5</a>.  This algorithm
     * requires a 512 bit (64 byte) key.
     */
    public static final AeadSymmetricEncryptionAlgorithm A256CBC_HS512 = hmac(256);

    /**
     * &quot;AES GCM using 128-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a>.  This algorithm requires
     * a 128 bit (16 byte) key.
     */
    public static final AeadSymmetricEncryptionAlgorithm A128GCM = gcm(128);

    /**
     * &quot;AES GCM using 192-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a>.  This algorithm requires
     * a 192 bit (24 byte) key.
     */
    public static final AeadSymmetricEncryptionAlgorithm A192GCM = gcm(192);

    /**
     * &quot;AES GCM using 256-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a>.  This algorithm requires
     * a 256 bit (32 byte) key.
     */
    public static final AeadSymmetricEncryptionAlgorithm A256GCM = gcm(256);

    private static final Map<String, AeadSymmetricEncryptionAlgorithm> SYMMETRIC_VALUES_BY_NAME = Collections.unmodifiableMap(Maps
        .of(A128CBC_HS256.getName(), A128CBC_HS256)
        .and(A192CBC_HS384.getName(), A192CBC_HS384)
        .and(A256CBC_HS512.getName(), A256CBC_HS512)
        .and(A128GCM.getName(), A128GCM)
        .and(A192GCM.getName(), A192GCM)
        .and(A256GCM.getName(), A256GCM)
        .build());

    public static EncryptionAlgorithm forName(String name) {
        Assert.hasText(name, "name cannot be null or empty.");
        EncryptionAlgorithm alg = SYMMETRIC_VALUES_BY_NAME.get(name.toUpperCase());
        if (alg == null) {
            String msg = "'" + name + "' is not a JWE specification standard name.  The standard names are: " +
            Strings.collectionToCommaDelimitedString(SYMMETRIC_VALUES_BY_NAME.keySet());
            throw new IllegalArgumentException(msg);
        }
        return alg;
    }

    public static Collection<AeadSymmetricEncryptionAlgorithm> symmetric() {
        return SYMMETRIC_VALUES_BY_NAME.values();
    }
}
