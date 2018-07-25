package io.jsonwebtoken.crypto;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import javax.crypto.SecretKey;
import java.security.KeyPair;

/**
 * Utility class for securely generating {@link SecretKey}s and {@link KeyPair}s.
 *
 * @since 0.10.0
 */
public final class Keys {

    private static final String MAC = "io.jsonwebtoken.impl.crypto.MacProvider";
    private static final String RSA = "io.jsonwebtoken.impl.crypto.RsaProvider";
    private static final String EC = "io.jsonwebtoken.impl.crypto.EllipticCurveProvider";

    private static final Class[] SIG_ARG_TYPES = new Class[]{SignatureAlgorithm.class};

    //prevent instantiation
    private Keys() {
    }

    /**
     * Returns a new {@link SecretKey} with a key length suitable for use with the specified {@link SignatureAlgorithm}.
     *
     * <p><a href="https://tools.ietf.org/html/rfc7518#section-3.2">JWA Specification (RFC 7518), Section 3.2</a>
     * requires minimum key lengths to be used for each respective Signature Algorithm.  This method returns a
     * secure-random generated SecretKey that adheres to the required minimum key length.  The lengths are:</p>
     *
     * <table>
     * <tr>
     * <th>Algorithm</th>
     * <th>Key Length</th>
     * </tr>
     * <tr>
     * <td>HS256</td>
     * <td>256 bits (32 bytes)</td>
     * </tr>
     * <tr>
     * <td>HS384</td>
     * <td>384 bits (48 bytes)</td>
     * </tr>
     * <tr>
     * <td>HS512</td>
     * <td>512 bits (64 bytes)</td>
     * </tr>
     * </table>
     *
     * @param alg the {@code SignatureAlgorithm} to inspect to determine which key length to use.
     * @return a new {@link SecretKey} instance suitable for use with the specified {@link SignatureAlgorithm}.
     * @throws IllegalArgumentException for any input value other than {@link SignatureAlgorithm#HS256},
     *                                  {@link SignatureAlgorithm#HS384}, or {@link SignatureAlgorithm#HS512}
     */
    public static SecretKey secretKeyFor(SignatureAlgorithm alg) throws IllegalArgumentException {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        switch (alg) {
            case HS256:
            case HS384:
            case HS512:
                return Classes.invokeStatic(MAC, "generateKey", SIG_ARG_TYPES, alg);
            default:
                String msg = "The " + alg.name() + " algorithm does not support shared secret keys.";
                throw new IllegalArgumentException(msg);
        }
    }

    /**
     * Returns a new {@link KeyPair} suitable for use with the specified asymmetric algorithm.
     *
     * <p>If the {@code alg} argument is an RSA algorithm, a KeyPair is generated based on the following:</p>
     *
     * <table>
     * <tr>
     * <th>JWA Algorithm</th>
     * <th>Key Size</th>
     * </tr>
     * <tr>
     * <td>RS256</td>
     * <td>2048 bits</td>
     * </tr>
     * <tr>
     * <td>PS256</td>
     * <td>2048 bits</td>
     * </tr>
     * <tr>
     * <td>RS384</td>
     * <td>3072 bits</td>
     * </tr>
     * <tr>
     * <td>PS256</td>
     * <td>3072 bits</td>
     * </tr>
     * <tr>
     * <td>RS512</td>
     * <td>4096 bits</td>
     * </tr>
     * <tr>
     * <td>PS512</td>
     * <td>4096 bits</td>
     * </tr>
     * </table>
     *
     * <p>If the {@code alg} argument is an Elliptic Curve algorithm, a KeyPair is generated based on the following:</p>
     *
     * <table>
     * <tr>
     * <th>JWA Algorithm</th>
     * <th>Key Size</th>
     * <th><a href="https://tools.ietf.org/html/rfc7518#section-7.6.2">JWA Curve Name</a></th>
     * <th><a href="https://tools.ietf.org/html/rfc5480#section-2.1.1.1">ASN1 OID Curve Name</a></th>
     * </tr>
     * <tr>
     * <td>EC256</td>
     * <td>256 bits</td>
     * <td>{@code P-256}</td>
     * <td>{@code secp256r1}</td>
     * </tr>
     * <tr>
     * <td>EC384</td>
     * <td>384 bits</td>
     * <td>{@code P-384}</td>
     * <td>{@code secp384r1}</td>
     * </tr>
     * <tr>
     * <td>EC512</td>
     * <td>512 bits</td>
     * <td>{@code P-512}</td>
     * <td>{@code secp521r1}</td>
     * </tr>
     * </table>
     *
     * @param alg the {@code SignatureAlgorithm} to inspect to determine which asymmetric algorithm to use.
     * @return a new {@link KeyPair} suitable for use with the specified asymmetric algorithm.
     * @throws IllegalArgumentException if {@code alg} equals {@link SignatureAlgorithm#HS256 HS256},
     *                                  {@link SignatureAlgorithm#HS384 HS384}, {@link SignatureAlgorithm#HS512 HS512}
     *                                  or {@link SignatureAlgorithm#NONE NONE}.
     */
    public static KeyPair keyPairFor(SignatureAlgorithm alg) throws IllegalArgumentException {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        switch (alg) {
            case RS256:
            case PS256:
            case RS384:
            case PS384:
            case RS512:
            case PS512:
                return Classes.invokeStatic(RSA, "generateKeyPair", SIG_ARG_TYPES, alg);
            case ES256:
            case ES384:
            case ES512:
                return Classes.invokeStatic(EC, "generateKeyPair", SIG_ARG_TYPES, alg);
            default:
                String msg = "The " + alg.name() + " algorithm does not support Key Pairs.";
                throw new IllegalArgumentException(msg);
        }
    }
}
