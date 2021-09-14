package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import javax.crypto.SecretKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @since JJWT_RELEASE_VERSION
 */
public final class KeyAlgorithms {

    //prevent instantiation
    private KeyAlgorithms() {
    }

    private static final String BRIDGE_CLASSNAME = "io.jsonwebtoken.impl.security.KeyAlgorithms";

    private static <T> T lookup(String methodName) {
        return Classes.invokeStatic(BRIDGE_CLASSNAME, methodName, null, (Object[]) null);
    }

    public static final KeyAlgorithm<SecretKey, SecretKey> DIRECT = lookup("direct");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> A128KW = lookup("a128kw");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> A192KW = lookup("a192kw");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> A256KW = lookup("a256kw");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> A128GCMKW = lookup("a128gcmkw");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> A192GCMKW = lookup("a192gcmkw");
    public static final EncryptedKeyAlgorithm<SecretKey, SecretKey> A256GCMKW = lookup("a256gcmkw");
    public static final EncryptedKeyAlgorithm<RSAPublicKey, RSAPrivateKey> RSA1_5 = lookup("rsa1_5");
    public static final EncryptedKeyAlgorithm<RSAPublicKey, RSAPrivateKey> RSA_OAEP = lookup("rsaOaep");
    public static final EncryptedKeyAlgorithm<RSAPublicKey, RSAPrivateKey> RSA_OAEP_256 = lookup("rsaOaep256");

    private static Map<String,KeyAlgorithm<?,?>> toMap(KeyAlgorithm<?,?>... algs) {
        Map<String, KeyAlgorithm<?,?>> m = new LinkedHashMap<>();
        for (KeyAlgorithm<?,?> alg : algs) {
            m.put(alg.getId(), alg);
        }
        return Collections.unmodifiableMap(m);
    }

    private static final Map<String,KeyAlgorithm<?,?>> STANDARD_ALGORITHMS = toMap(
        DIRECT, A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW, A256GCMKW, RSA1_5, RSA_OAEP, RSA_OAEP_256
    );

    public static Collection<? extends KeyAlgorithm<?,?>> values() {
        return STANDARD_ALGORITHMS.values();
    }

    /**
     * Looks up and returns the corresponding JWA standard {@code KeyAlgorithm} instance based on a
     * case-<em>insensitive</em> name comparison.
     *
     * @param id The case-insensitive identifier of the JWA standard {@code KeyAlgorithm} instance to return
     * @return the corresponding JWA standard {@code KeyAlgorithm} enum instance based on a
     * case-<em>insensitive</em> name comparison.
     * @throws SignatureException if the specified value does not match any JWA standard {@code KeyAlgorithm} name.
     */
    public static KeyAlgorithm<?,?> forName(String id) {
        Assert.hasText(id, "id argument cannot be null or empty.");
        //try constant time lookup first.  This will satisfy 99% of invocations:
        KeyAlgorithm<?,?> alg = STANDARD_ALGORITHMS.get(id);
        if (alg != null) {
            return alg;
        }
        //fall back to case-insensitive lookup:
        for (KeyAlgorithm<?,?> kalg : STANDARD_ALGORITHMS.values()) {
            if (id.equalsIgnoreCase(kalg.getId())) {
                return kalg;
            }
        }
        // still no result - error:
        throw new IllegalArgumentException("Unrecognized key algorithm id '" + id + "'");
    }
}
