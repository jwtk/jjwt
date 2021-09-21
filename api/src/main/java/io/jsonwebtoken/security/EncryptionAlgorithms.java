package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import java.util.Collection;

/**
 * @since JJWT_RELEASE_VERSION
 */
public final class EncryptionAlgorithms {

    //prevent instantiation
    private EncryptionAlgorithms() {
    }

    private static final String BRIDGE_CLASSNAME = "io.jsonwebtoken.impl.security.EncryptionAlgorithmsBridge";
    private static final Class<?>[] ID_ARG_TYPES = new Class[]{String.class};

    public static Collection<SymmetricAeadAlgorithm> values() {
        return Classes.invokeStatic(BRIDGE_CLASSNAME, "values", null, (Object[]) null);
    }

    /**
     * Returns the JWE Encryption Algorithm with the specified
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-5.1">{@code enc} algorithm identifier</a> or
     * {@code null} if an algorithm for the specified {@code id} cannot be found.
     *
     * @param id a JWE standard {@code enc} algorithm identifier
     * @return the associated Encryption Algorithm instance or {@code null} otherwise.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-5.1">RFC 7518, Section 5.1</a>
     */
    public static SymmetricAeadAlgorithm findById(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASSNAME, "findById", ID_ARG_TYPES, id);
    }

    private static SymmetricAeadAlgorithm forId(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASSNAME, "forId", ID_ARG_TYPES, id);
    }

    /**
     * AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.3">RFC 7518, Section 5.2.3</a>.  This algorithm
     * requires a 256 bit (32 byte) key.
     */
    public static final SymmetricAeadAlgorithm A128CBC_HS256 = forId("A128CBC-HS256");

    /**
     * AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.4">RFC 7518, Section 5.2.4</a>. This algorithm
     * requires a 384 bit (48 byte) key.
     */
    public static final SymmetricAeadAlgorithm A192CBC_HS384 = forId("A192CBC-HS384");

    /**
     * AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm, as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.2.5">RFC 7518, Section 5.2.5</a>.  This algorithm
     * requires a 512 bit (64 byte) key.
     */
    public static final SymmetricAeadAlgorithm A256CBC_HS512 = forId("A256CBC-HS512");

    /**
     * &quot;AES GCM using 128-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a>.  This algorithm requires
     * a 128 bit (16 byte) key.
     */
    public static final SymmetricAeadAlgorithm A128GCM = forId("A128GCM");

    /**
     * &quot;AES GCM using 192-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a>.  This algorithm requires
     * a 192 bit (24 byte) key.
     */
    public static final SymmetricAeadAlgorithm A192GCM = forId("A192GCM");

    /**
     * &quot;AES GCM using 256-bit key&quot; as defined by
     * <a href="https://tools.ietf.org/html/rfc7518#section-5.3">RFC 7518, Section 5.3</a>.  This algorithm requires
     * a 256 bit (32 byte) key.
     */
    public static final SymmetricAeadAlgorithm A256GCM = forId("A256GCM");
}
