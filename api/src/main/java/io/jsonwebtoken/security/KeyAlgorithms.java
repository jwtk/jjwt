package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import javax.crypto.SecretKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;

/**
 * @since JJWT_RELEASE_VERSION
 */
public final class KeyAlgorithms {

    //prevent instantiation
    private KeyAlgorithms() {
    }

    private static final String BRIDGE_CLASSNAME = "io.jsonwebtoken.impl.security.KeyAlgorithmsBridge";
    private static final Class<?>[] ID_ARG_TYPES = new Class[]{String.class};

    public static Collection<SymmetricAeadAlgorithm> values() {
        return Classes.invokeStatic(BRIDGE_CLASSNAME, "values", null, (Object[]) null);
    }

    /**
     * Returns the JWE KeyAlgorithm with the specified
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.1">{@code alg} key algorithm identifier</a> or
     * {@code null} if an algorithm for the specified {@code id} cannot be found.
     *
     * @param id a JWE standard {@code alg} key algorithm identifier
     * @return the associated KeyAlgorithm instance or {@code null} otherwise.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.1">RFC 7518, Section 4.1</a>
     */
    public static KeyAlgorithm<?, ?> findById(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASSNAME, "findById", ID_ARG_TYPES, id);
    }

    public static KeyAlgorithm<?, ?> forId(String id) {
        return forId0(id);
    }

    // do not change this visibility.  Raw type method signature not be publicly exposed
    private static <T> T forId0(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASSNAME, "forId", ID_ARG_TYPES, id);
    }

    public static final KeyAlgorithm<SecretKey, SecretKey> DIRECT = forId0("dir");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> A128KW = forId0("A128KW");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> A192KW = forId0("A192KW");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> A256KW = forId0("A256KW");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> A128GCMKW = forId0("A128GCMKW");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> A192GCMKW = forId0("A192GCMKW");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> A256GCMKW = forId0("A256GCMKW");
    public static final EncryptedKeyAlgorithm<RSAPublicKey, RSAPrivateKey> RSA1_5 = forId0("RSA1_5");
    public static final EncryptedKeyAlgorithm<RSAPublicKey, RSAPrivateKey> RSA_OAEP = forId0("RSA-OAEP");
    public static final EncryptedKeyAlgorithm<RSAPublicKey, RSAPrivateKey> RSA_OAEP_256 = forId0("RSA-OAEP-256");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> PBES2_HS256_A128KW = forId0("PBES2-HS256+A128KW");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> PBES2_HS384_A192KW = forId0("PBES2-HS384+A192KW");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> PBES2_HS512_A256KW = forId0("PBES2-HS512+A256KW");
}
