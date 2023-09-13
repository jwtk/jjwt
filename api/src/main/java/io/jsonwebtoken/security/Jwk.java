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

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.lang.Supplier;

import java.security.Key;
import java.util.Map;
import java.util.Set;

/**
 * A JWK is an immutable set of name/value pairs that represent a cryptographic key as defined by
 * <a href="https://www.rfc-editor.org/rfc/rfc7517.html">RFC 7517: JSON Web Key (JWK)</a>.  The {@code Jwk}
 * interface represents properties common to all JWKs.  Subtypes will have additional properties specific to
 * different types of cryptographic keys (e.g. Secret, Asymmetric, RSA, Elliptic Curve, etc).
 *
 * <p><b>Immutability</b></p>
 *
 * <p>JWKs are immutable and cannot be changed after they are created.  {@code Jwk} extends the
 * {@link Map} interface purely out of convenience: to allow easy marshalling to JSON as well as name/value
 * pair access and key/value iteration, and other conveniences provided by the Map interface.  Attempting to call any of
 * the {@link Map} interface's mutation methods however (such as {@link Map#put(Object, Object) put},
 * {@link Map#remove(Object) remove}, {@link Map#clear() clear}, etc) will throw an
 * {@link UnsupportedOperationException}.</p>
 *
 * <p><b>Identification</b></p>
 *
 * <p>{@code Jwk} extends {@link Identifiable} to support the
 * <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.5">JWK {@code kid} parameter</a>. Calling
 * {@link #getId() aJwk.getId()} is the type-safe idiomatic approach to the alternative equivalent of
 * {@code aJwk.get("kid")}. Either approach will return an id if one was originally set on the JWK, or {@code null} if
 * an id does not exist.</p>
 *
 * <p><b>Private and Secret Value Safety</b></p>
 *
 * <p>JWKs often represent secret or private key data which should never be exposed publicly, nor mistakenly printed
 * to application logs or {@code System.out.println} calls.  As a result, all JJWT JWK
 * private or secret values are 'wrapped' in a {@link io.jsonwebtoken.lang.Supplier Supplier} instance to ensure
 * any attempt to call {@link String#toString() toString()} on the value will print a redacted value instead of an
 * actual private or secret value.</p>
 *
 * <p>For example, a {@link SecretJwk} will have an internal &quot;{@code k}&quot; member whose value reflects raw
 * key material that should always be kept secret.  If the following is called:</p>
 * <blockquote><pre>
 * System.out.println(aSecretJwk.get(&quot;k&quot;));</pre></blockquote>
 * <p>You would see the following:</p>
 * <blockquote><pre>
 * &lt;redacted&gt;</pre></blockquote>
 * <p>instead of the actual/raw {@code k} value.</p>
 *
 * <p>Similarly, if attempting to print the entire JWK:</p>
 * <blockquote><pre>
 * System.out.println(aSecretJwk);</pre></blockquote>
 * <p>You would see the following substring in the output:</p>
 * <blockquote><pre>
 * k=&lt;redacted&gt;</pre></blockquote>
 * <p>instead of the actual/raw {@code k} value.</p>
 *
 * <p>Finally, because all private or secret values are wrapped as {@link io.jsonwebtoken.lang.Supplier}
 * instances, if you really wanted the <em>real</em> internal value, you could just call the supplier's
 * {@link Supplier#get() get()} method:</p>
 * <blockquote><pre>
 * String k = ((Supplier&lt;String&gt;)aSecretJwk.get(&quot;k&quot;)).get();</pre></blockquote>
 * <p>but <b><em>BE CAREFUL</em></b>: obtaining the raw value in your application code exposes greater security
 * risk - you must ensure to keep that value safe and out of console or log output.  It is almost always better to
 * interact with the JWK's {@link #toKey() toKey()} instance directly instead of accessing
 * JWK internal serialization parameters.</p>
 *
 * @param <K> The type of Java {@link Key} represented by this JWK
 * @since JJWT_RELEASE_VERSION
 */
public interface Jwk<K extends Key> extends Identifiable, Map<String, Object> {

    /**
     * Returns the JWK
     * <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.4">{@code alg} (Algorithm)</a> value
     * or {@code null} if not present.
     *
     * @return the JWK {@code alg} value or {@code null} if not present.
     */
    String getAlgorithm();

    /**
     * Returns the JWK <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3">{@code key_ops}
     * (Key Operations) parameter</a> values or {@code null} if not present.  All JWK standard Key Operations are
     * available via the {@link Jwks.OP} registry, but other (custom) values <em>MAY</em> be present in the returned
     * set.
     *
     * @return the JWK {@code key_ops} value or {@code null} if not present.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3"><code>key_ops</code>(Key Operations) Parameter</a>
     */
    Set<KeyOperation> getOperations();

    /**
     * Returns the required JWK
     * <a href="https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1">{@code kty} (Key Type)
     * parameter</a> value. A value is required and may not be {@code null}.
     *
     * <p>The JWA specification <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1">defines</a> the
     * following {@code kty} values:</p>
     *
     * <table>
     * <caption>JWK Key Types</caption>
     * <thead>
     * <tr>
     * <th>Value</th>
     * <th>Key Type</th>
     * </tr>
     * </thead>
     * <tbody>
     * <tr>
     * <td><b>{@code EC}</b></td>
     * <td>Elliptic Curve [<a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">DSS</a>]</td>
     * </tr>
     * <tr>
     * <td><b>{@code RSA}</b></td>
     * <td>RSA [<a href="https://datatracker.ietf.org/doc/html/rfc3447">RFC 3447</a>]</td>
     * </tr>
     * <tr>
     * <td><b>{@code oct}</b></td>
     * <td>Octet sequence (used to represent symmetric keys)</td>
     * </tr>
     * <tr>
     * <td><b>{@code OKP}</b></td>
     * <td><a href="https://www.rfc-editor.org/rfc/rfc8037#section-2">Octet Key Pair</a> (used to represent Edwards
     * Elliptic Curve keys)</td>
     * </tr>
     * </tbody>
     * </table>
     *
     * @return the JWK {@code kty} (Key Type) value.
     */
    String getType();

    /**
     * Computes and returns the canonical <a href="https://www.rfc-editor.org/rfc/rfc7638">JWK Thumbprint</a> of this
     * JWK using the {@code SHA-256} hash algorithm.  This is a convenience method that delegates to
     * {@link #thumbprint(HashAlgorithm)} with a {@code SHA-256} {@link HashAlgorithm} instance.
     *
     * @return the canonical <a href="https://www.rfc-editor.org/rfc/rfc7638">JWK Thumbprint</a> of this
     * JWK using the {@code SHA-256} hash algorithm.
     * @see #thumbprint(HashAlgorithm)
     */
    JwkThumbprint thumbprint();

    /**
     * Computes and returns the canonical <a href="https://www.rfc-editor.org/rfc/rfc7638">JWK Thumbprint</a> of this
     * JWK using the specified hash algorithm.
     *
     * @param alg the hash algorithm to use to compute the digest of the canonical JWK Thumbprint JSON form of this JWK.
     * @return the canonical <a href="https://www.rfc-editor.org/rfc/rfc7638">JWK Thumbprint</a> of this
     * JWK using the specified hash algorithm.
     */
    JwkThumbprint thumbprint(HashAlgorithm alg);

    /**
     * Represents the JWK as its corresponding Java {@link Key} instance for use with Java cryptographic
     * APIs.
     *
     * @return the JWK's corresponding Java {@link Key} instance for use with Java cryptographic APIs.
     */
    K toKey();
}
