package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @since JJWT_RELEASE_VERSION
 */
public final class SignatureAlgorithms {

    // Prevent instantiation
    private SignatureAlgorithms() {
    }

    static final String HMAC = "io.jsonwebtoken.impl.security.MacSignatureAlgorithm";
    static final Class<?>[] HMAC_ARGS = new Class[]{String.class, String.class, int.class};

    private static final String RSA = "io.jsonwebtoken.impl.security.RsaSignatureAlgorithm";
    private static final Class<?>[] RSA_ARGS = new Class[]{String.class, String.class, int.class};
    private static final Class<?>[] PSS_ARGS = new Class[]{String.class, String.class, int.class, int.class};

    private static final String EC = "io.jsonwebtoken.impl.security.EllipticCurveSignatureAlgorithm";
    private static final Class<?>[] EC_ARGS = new Class[]{String.class, String.class, String.class, int.class, int.class};

    private static SymmetricKeySignatureAlgorithm hmacSha(int minKeyLength) {
        return Classes.newInstance(HMAC, HMAC_ARGS, "HS" + minKeyLength, "HmacSHA" + minKeyLength, minKeyLength);
    }

    private static AsymmetricKeySignatureAlgorithm rsa(int digestLength, int preferredKeyLength) {
        return Classes.newInstance(RSA, RSA_ARGS, "RS" + digestLength, "SHA" + digestLength + "withRSA", preferredKeyLength);
    }

    private static AsymmetricKeySignatureAlgorithm pss(int digestLength, int preferredKeyLength) {
        return Classes.newInstance(RSA, PSS_ARGS, "PS" + digestLength, "RSASSA-PSS", preferredKeyLength, digestLength);
    }

    private static AsymmetricKeySignatureAlgorithm ec(int keySize, int signatureLength) {
        int shaSize = keySize == 521 ? 512 : keySize;
        return Classes.newInstance(EC, EC_ARGS, "ES" + shaSize, "SHA" + shaSize + "withECDSA", "secp" + keySize + "r1", keySize, signatureLength);
    }

    public static final SignatureAlgorithm NONE = Classes.newInstance("io.jsonwebtoken.impl.security.NoneSignatureAlgorithm");
    public static final SymmetricKeySignatureAlgorithm HS256 = hmacSha(256);
    public static final SymmetricKeySignatureAlgorithm HS384 = hmacSha(384);
    public static final SymmetricKeySignatureAlgorithm HS512 = hmacSha(512);
    public static final AsymmetricKeySignatureAlgorithm RS256 = rsa(256, 2048);
    public static final AsymmetricKeySignatureAlgorithm RS384 = rsa(384, 3072);
    public static final AsymmetricKeySignatureAlgorithm RS512 = rsa(512, 4096);
    public static final AsymmetricKeySignatureAlgorithm PS256 = pss(256, 2048);
    public static final AsymmetricKeySignatureAlgorithm PS384 = pss(384, 3072);
    public static final AsymmetricKeySignatureAlgorithm PS512 = pss(512, 4096);
    public static final AsymmetricKeySignatureAlgorithm ES256 = ec(256, 64);
    public static final AsymmetricKeySignatureAlgorithm ES384 = ec(384, 96);
    public static final AsymmetricKeySignatureAlgorithm ES512 = ec(521, 132);

    private static Map<String, SignatureAlgorithm> toMap(SignatureAlgorithm... algs) {
        Map<String, SignatureAlgorithm> m = new LinkedHashMap<>();
        for (SignatureAlgorithm alg : algs) {
            m.put(alg.getName(), alg);
        }
        return Collections.unmodifiableMap(m);
    }

    private static final Map<String, SignatureAlgorithm> STANDARD_ALGORITHMS = toMap(
        NONE, HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512
    );

    public static Collection<? extends SignatureAlgorithm> values() {
        return STANDARD_ALGORITHMS.values();
    }

    /**
     * Looks up and returns the corresponding JWA standard {@code SignatureAlgorithm} instance based on a
     * case-<em>insensitive</em> name comparison.
     *
     * @param name The case-insensitive name of the JWA standard {@code SignatureAlgorithm} instance to return
     * @return the corresponding JWA standard {@code SignatureAlgorithm} enum instance based on a
     * case-<em>insensitive</em> name comparison.
     * @throws SignatureException if the specified value does not match any JWA standard {@code SignatureAlgorithm}
     *                            name.
     */
    public static SignatureAlgorithm forName(String name) {
        Assert.notNull(name, "name argument cannot be null.");
        //try constant time lookup first.  This will satisfy 99% of invocations:
        SignatureAlgorithm alg = STANDARD_ALGORITHMS.get(name);
        if (alg != null) {
            return alg;
        }
        //fall back to case-insensitive lookup:
        for (SignatureAlgorithm salg : STANDARD_ALGORITHMS.values()) {
            if (name.equalsIgnoreCase(salg.getName())) {
                return salg;
            }
        }
        // still no result - error:
        throw new SignatureException("Unsupported signature algorithm '" + name + "'");
    }

    /**
     * Returns the recommended signature algorithm to be used with the specified key according to the following
     * heuristics:
     *
     * <table>
     * <caption>Key Signature Algorithm</caption>
     * <thead>
     * <tr>
     * <th>If the Key is a:</th>
     * <th>And:</th>
     * <th>With a key size of:</th>
     * <th>The returned SignatureAlgorithm will be:</th>
     * </tr>
     * </thead>
     * <tbody>
     * <tr>
     * <td>{@link SecretKey}</td>
     * <td><code>{@link Key#getAlgorithm() getAlgorithm()}.equals("HmacSHA256")</code><sup>1</sup></td>
     * <td>256 &lt;= size &lt;= 383 <sup>2</sup></td>
     * <td>{@link SignatureAlgorithms#HS256 HS256}</td>
     * </tr>
     * <tr>
     * <td>{@link SecretKey}</td>
     * <td><code>{@link Key#getAlgorithm() getAlgorithm()}.equals("HmacSHA384")</code><sup>1</sup></td>
     * <td>384 &lt;= size &lt;= 511</td>
     * <td>{@link SignatureAlgorithms#HS384 HS384}</td>
     * </tr>
     * <tr>
     * <td>{@link SecretKey}</td>
     * <td><code>{@link Key#getAlgorithm() getAlgorithm()}.equals("HmacSHA512")</code><sup>1</sup></td>
     * <td>512 &lt;= size</td>
     * <td>{@link SignatureAlgorithms#HS512 HS512}</td>
     * </tr>
     * <tr>
     * <td>{@link ECKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>256 &lt;= size &lt;= 383 <sup>3</sup></td>
     * <td>{@link SignatureAlgorithms#ES256 ES256}</td>
     * </tr>
     * <tr>
     * <td>{@link ECKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>384 &lt;= size &lt;= 520 <sup>4</sup></td>
     * <td>{@link SignatureAlgorithms#ES384 ES384}</td>
     * </tr>
     * <tr>
     * <td>{@link ECKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td><b>521</b> &lt;= size <sup>4</sup></td>
     * <td>{@link SignatureAlgorithms#ES512 ES512}</td>
     * </tr>
     * <tr>
     * <td>{@link RSAKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>2048 &lt;= size &lt;= 3071 <sup>5,6</sup></td>
     * <td>{@link SignatureAlgorithms#RS256 RS256}</td>
     * </tr>
     * <tr>
     * <td>{@link RSAKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>3072 &lt;= size &lt;= 4095 <sup>6</sup></td>
     * <td>{@link SignatureAlgorithms#RS384 RS384}</td>
     * </tr>
     * <tr>
     * <td>{@link RSAKey}</td>
     * <td><code>instanceof {@link PrivateKey}</code></td>
     * <td>4096 &lt;= size <sup>5</sup></td>
     * <td>{@link SignatureAlgorithms#RS512 RS512}</td>
     * </tr>
     * </tbody>
     * </table>
     * <p>Notes:</p>
     * <ol>
     * <li>{@code SecretKey} instances must have an {@link Key#getAlgorithm() algorithm} name equal
     * to {@code HmacSHA256}, {@code HmacSHA384} or {@code HmacSHA512}.  If not, the key bytes might not be
     * suitable for HMAC signatures will be rejected with a {@link InvalidKeyException}. </li>
     * <li>The JWT <a href="https://tools.ietf.org/html/rfc7518#section-3.2">JWA Specification (RFC 7518,
     * Section 3.2)</a> mandates that HMAC-SHA-* signing keys <em>MUST</em> be 256 bits or greater.
     * {@code SecretKey}s with key lengths less than 256 bits will be rejected with an
     * {@link WeakKeyException}.</li>
     * <li>The JWT <a href="https://tools.ietf.org/html/rfc7518#section-3.4">JWA Specification (RFC 7518,
     * Section 3.4)</a> mandates that ECDSA signing key lengths <em>MUST</em> be 256 bits or greater.
     * {@code ECKey}s with key lengths less than 256 bits will be rejected with a
     * {@link WeakKeyException}.</li>
     * <li>The ECDSA {@code P-521} curve does indeed use keys of <b>521</b> bits, not 512 as might be expected.  ECDSA
     * keys of 384 < size <= 520 are suitable for ES384, while ES512 requires keys >= 521 bits.  The '512' part of the
     * ES512 name reflects the usage of the SHA-512 algorithm, not the ECDSA key length.  ES512 with ECDSA keys less
     * than 521 bits will be rejected with a {@link WeakKeyException}.</li>
     * <li>The JWT <a href="https://tools.ietf.org/html/rfc7518#section-3.3">JWA Specification (RFC 7518,
     * Section 3.3)</a> mandates that RSA signing key lengths <em>MUST</em> be 2048 bits or greater.
     * {@code RSAKey}s with key lengths less than 2048 bits will be rejected with a
     * {@link WeakKeyException}.</li>
     * <li>Technically any RSA key of length >= 2048 bits may be used with the {@link #RS256}, {@link #RS384}, and
     * {@link #RS512} algorithms, so we assume an RSA signature algorithm based on the key length to
     * parallel similar decisions in the JWT specification for HMAC and ECDSA signature algorithms.
     * This is not required - just a convenience.</li>
     * </ol>
     * <p>This implementation does not return the {@link #PS256}, {@link #PS256}, {@link #PS256} RSA variants for any
     * specified {@link RSAKey} because the the {@link #RS256}, {@link #RS384}, and {@link #RS512} algorithms are
     * available in the JDK by default while the {@code PS}* variants require either JDK 11 or an additional JCA
     * Provider (like BouncyCastle).</p>
     * <p>Finally, this method will throw an {@link InvalidKeyException} for any key that does not match the
     * heuristics and requirements documented above, since that inevitably means the Key is either insufficient or
     * explicitly disallowed by the JWT specification.</p>
     *
     * @param key the key to inspect
     * @return the recommended signature algorithm to be used with the specified key
     * @throws InvalidKeyException for any key that does not match the heuristics and requirements documented above,
     *                             since that inevitably means the Key is either insufficient or explicitly disallowed by the JWT specification.
     */
    public static SignatureAlgorithm forSigningKey(Key key) {
        io.jsonwebtoken.SignatureAlgorithm alg = io.jsonwebtoken.SignatureAlgorithm.forSigningKey(key);
        return forName(alg.getValue());
    }
}
