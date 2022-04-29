/*
 * Copyright (C) 2021 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Collection;

/**
 * @since JJWT_RELEASE_VERSION
 */
@SuppressWarnings({"rawtypes", "JavadocLinkAsPlainText"})
public final class SignatureAlgorithms {

    // Prevent instantiation
    private SignatureAlgorithms() {
    }

    private static final String BRIDGE_CLASSNAME = "io.jsonwebtoken.impl.security.SignatureAlgorithmsBridge";
    private static final Class<?> BRIDGE_CLASS = Classes.forName(BRIDGE_CLASSNAME);
    private static final Class<?>[] ID_ARG_TYPES = new Class[]{String.class};

    public static Collection<SignatureAlgorithm<?,?>> values() {
        return Classes.invokeStatic(BRIDGE_CLASS, "values", null, (Object[]) null);
    }

    public static SignatureAlgorithm<?, ?> findById(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASS, "findById", ID_ARG_TYPES, id);
    }

    public static SignatureAlgorithm<?,?> forId(String id) {
        return forId0(id);
    }

    static <T> T forId0(String id) {
        Assert.hasText(id, "id cannot be null or empty.");
        return Classes.invokeStatic(BRIDGE_CLASS, "forId", ID_ARG_TYPES, id);
    }

    public static final SignatureAlgorithm<Key, Key> NONE = forId0("none");
    public static final SecretKeySignatureAlgorithm HS256 = forId0("HS256");
    public static final SecretKeySignatureAlgorithm HS384 = forId0("HS384");
    public static final SecretKeySignatureAlgorithm HS512 = forId0("HS512");
    public static final RsaSignatureAlgorithm RS256 = forId0("RS256");
    public static final RsaSignatureAlgorithm RS384 = forId0("RS384");
    public static final RsaSignatureAlgorithm RS512 = forId0("RS512");
    public static final RsaSignatureAlgorithm PS256 = forId0("PS256");
    public static final RsaSignatureAlgorithm PS384 = forId0("PS384");
    public static final RsaSignatureAlgorithm PS512 = forId0("PS512");
    public static final EllipticCurveSignatureAlgorithm ES256 = forId0("ES256");
    public static final EllipticCurveSignatureAlgorithm ES384 = forId0("ES384");
    public static final EllipticCurveSignatureAlgorithm ES512 = forId0("ES512");

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
     * keys of 384 &lt; size &lt;= 520 are suitable for ES384, while ES512 requires keys &gt;= 521 bits.  The '512' part of the
     * ES512 name reflects the usage of the SHA-512 algorithm, not the ECDSA key length.  ES512 with ECDSA keys less
     * than 521 bits will be rejected with a {@link WeakKeyException}.</li>
     * <li>The JWT <a href="https://tools.ietf.org/html/rfc7518#section-3.3">JWA Specification (RFC 7518,
     * Section 3.3)</a> mandates that RSA signing key lengths <em>MUST</em> be 2048 bits or greater.
     * {@code RSAKey}s with key lengths less than 2048 bits will be rejected with a
     * {@link WeakKeyException}.</li>
     * <li>Technically any RSA key of length &gt;= 2048 bits may be used with the {@link #RS256}, {@link #RS384}, and
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
    public static SignatureAlgorithm<?, ?> forSigningKey(Key key) {
        @SuppressWarnings("deprecation")
        io.jsonwebtoken.SignatureAlgorithm alg = io.jsonwebtoken.SignatureAlgorithm.forSigningKey(key);
        return forId(alg.getValue());
    }
}
