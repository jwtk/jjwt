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

import java.security.Key;
import java.util.Map;
import java.util.Set;

/**
 * A JWK is an immutable set of name/value pairs that represent a cryptographic key as defined by
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517">RFC 7517: JSON Web Key (JWK)</a>.  The {@code Jwk}
 * interface represents JWK properties accessible for any JWK.  Subtypes will have additional JWK properties
 * specific to different types of cryptographic keys (e.g. Secret, Asymmetric, RSA, Elliptic Curve, etc).
 *
 * <p><b>Immutability</b></p>
 *
 * <p>JWKs are immutable and cannot be changed after they are created.  {@code Jwk} extends the
 * {@link Map} interface purely out of convenience: to allow easy marshalling to JSON as well as name/value
 * pair access and key/value iteration, and other conveniences provided by the Map interface.  Attempting to call any of
 * the {@link Map} interface's mutation methods however (such as {@link Map#put(Object, Object) put},
 * {@link Map#remove(Object) remove}, {@link Map#clear() clear}, etc) will result in an
 * {@link UnsupportedOperationException} being thrown.</p>
 *
 * <p><b>Identification</b></p>
 *
 * <p>{@code Jwk} extends {@link Identifiable} to support the
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.5">JWK {@code kid} parameter</a>. Calling
 * {@link #getId() aJwk.getId()} is the type-safe idiomatic approach to the alternative equivalent of
 * {@code aJwk.get("kid")}. Either approach will return an id if one was originally set on the JWK, or {@code null} if
 * an id does not exist.</p>
 *
 * <p><b>toString Safety</b></p>
 *
 * <p>JWKs often represent secret or private key data which should never be exposed publicly, nor mistakenly printed
 * via application logs or {@code System.out.println} calls.  As a result, all JJWT JWK
 * {@link String#toString() toString()} implementations automatically print redacted values instead actual
 * values for any private or secret fields.</p>
 *
 * <p>For example, a {@link SecretJwk} will have an internal &quot;{@code k}&quot; member whose value reflects raw
 * key material that should always be kept secret. If {@code aSecretJwk.toString()} is called, the resulting string
 * will contain the substring <code>k=&lt;redacted&gt;</code>, instead of the actual {@code k} value.  The string
 * literal <code>&lt;redacted&gt;</code> is printed everywhere a private or secret value would have otherwise.</p>
 *
 * <p><b>WARNING:</b> Note however, certain JVM programming languages (like
 * <a href="https://stackoverflow.com/questions/45383815/groovy-gstring-rendering-does-not-call-overridden-tostring-method-when-parent">
 * Groovy for example</a>) when encountering a
 * Map or Collection instance, will <em>NOT</em> always call an object's {@code toString()} method when rendering
 * strings.  <b>Because all JJWT JWKs implement the {@link Map Map} interface, in these language environments,
 * you must explicitly call {@code aJwk.toString()} method to override the language's built-in string rendering to
 * ensure key safety.</b> This is not a concern if using the Java language directly.</p>
 *
 * <p>For example, this is safe in Java:</p>
 * <pre><code>
 *     String s = "My JWK is: " + aSecretJwk; //or String.format("My JWK is: %s", aSecretJwk)
 *     System.out.println(s);
 * </code></pre>
 *
 * <p>Whereas the same is NOT SAFE in Groovy:</p>
 * <pre><code>
 *     println "My JWK is: ${aSecretJwk}" // or "My JWK is " + aSecretJwk
 * </code></pre>
 *
 * <p>But the following IS safe in Groovy:</p>
 * <pre><code>
 *     println "My JWK is: ${aSecretJwk.toString()}" // or "My JWK is " + aSecretJwk.toString()
 * </code></pre>
 * <p>Because Groovy's {@code GString} concept does not call {@code Map#toString()} directly and creates its own
 * toString implementation with the raw name/value pairs, you must call {@link String#toString() toString()}
 * explicitly.</p>
 *
 * <p>If you are using an alternative JVM programming language other than Java, understand your language
 * environment's String rendering behavior and adjust for explicit {@code toString()} calls as necessary.</p>
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface Jwk<K extends Key> extends Identifiable, Map<String, Object> {

    /**
     * Returns the JWK
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.4">{@code alg} (Algorithm) parameter</a> value
     * or {@code null} if not present.
     *
     * @return the JWK {@code alg} value or {@code null} if not present.
     */
    String getAlgorithm();

    /**
     * Returns the JWK
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.3">{@code key_ops} (Key Operations)
     * parameter</a> values or {@code null} if not present.  Any values within the returned {@code Set} are
     * CaSe-SeNsItIvE.
     *
     * <p>The JWK specification <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.3">defines</a> the
     * following values:</p>
     *
     * <table>
     * <caption>JWK Key Operations</caption>
     * <thead>
     * <tr>
     * <th>Value</th>
     * <th>Operation</th>
     * </tr>
     * </thead>
     * <tbody>
     * <tr>
     * <td><b>{@code sign}</b></td>
     * <td>compute digital signatures or MAC</td>
     * </tr>
     * <tr>
     * <td><b>{@code verify}</b></td>
     * <td>verify digital signatures or MAC</td>
     * </tr>
     * <tr>
     * <td><b>{@code encrypt}</b></td>
     * <td>encrypt content</td>
     * </tr>
     * <tr>
     * <td><b>{@code decrypt}</b></td>
     * <td>decrypt content and validate decryption, if applicable</td>
     * </tr>
     * <tr>
     * <td><b>{@code wrapKey}</b></td>
     * <td>encrypt key</td>
     * </tr>
     * <tr>
     * <td><b>{@code unwrapKey}</b></td>
     * <td>decrypt key and validate decryption, if applicable</td>
     * </tr>
     * <tr>
     * <td><b>{@code deriveKey}</b></td>
     * <td>derive key</td>
     * </tr>
     * <tr>
     * <td><b>{@code deriveBits}</b></td>
     * <td>derive bits not to be used as a key</td>
     * </tr>
     * </tbody>
     * </table>
     *
     * <p>Other values <em>MAY</em> be used.  For best interoperability with other applications however, it is
     * recommended to use only the values above.</p>
     *
     * <p>Multiple unrelated key operations <em>SHOULD NOT</em> be specified for a key because of the potential
     * vulnerabilities associated with using the same key with multiple algorithms.  Thus, the combinations
     * {@code sign} with {@code verify}, {@code encrypt} with {@code decrypt}, and {@code wrapKey} with
     * {@code unwrapKey} are permitted, but other combinations <em>SHOULD NOT</em> be used.</p>
     *
     * @return the JWK {@code key_ops} value or {@code null} if not present.
     */
    Set<String> getOperations();

    /**
     * Returns the required JWK
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.1">{@code kty} (Key Type)
     * parameter</a> value. A value is required and may not be {@code null}.
     *
     * <p>The JWA specification <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.1">defines</a> the
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
     * </tbody>
     * </table>
     *
     * @return the JWK {@code kty} (Key Type) value.
     */
    String getType();

    /**
     * Converts the JWK to its corresponding Java {@link Key} instance for use with Java cryptographic
     * APIs.
     *
     * @return the corresponding Java {@link Key} instance for use with Java cryptographic APIs.
     */
    K toKey();
}
