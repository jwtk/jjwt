/*
 * Copyright © 2023 jsonwebtoken.io
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
import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Registry;

import java.util.Collection;

/**
 * Registry of various (<em>but not all</em>)
 * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
 * Algorithms</a> commonly used to compute {@link JwkThumbprint JWK Thumbprint}s and ensure valid
 * <a href="https://www.rfc-editor.org/rfc/rfc9278#name-hash-algorithms-identifier">JWK Thumbprint URIs</a>.  For
 * example:
 * <blockquote><pre>
 * Jwks.{@link  JwkBuilder builder}()
 *     // ... etc ...
 *     .{@link JwkBuilder#setIdFromThumbprint(HashAlgorithm) setIdFromThumbprint}(Jwks.HASH.{@link StandardHashAlgorithms#SHA256 SHA256}) // &lt;---
 *     .build()</pre></blockquote>
 * <p>or</p>
 * <blockquote><pre>
 * HashAlgorithm hashAlg = Jwks.HASH.{@link StandardHashAlgorithms#SHA256 SHA256};
 * {@link JwkThumbprint} thumbprint = aJwk.{@link Jwk#thumbprint(HashAlgorithm) thumbprint}(hashAlg);
 * String <a href="https://www.rfc-editor.org/rfc/rfc9278#section-3">rfcMandatoryPrefix</a> = "urn:ietf:params:oauth:jwk-thumbprint:" + hashAlg.getId();
 * assert thumbprint.toURI().toString().startsWith(rfcMandatoryPrefix);
 * </pre></blockquote>
 *
 * @see #get()
 * @see #values()
 * @see Registry#get(Object)
 * @see #forKey(String)
 * @see HashAlgorithm
 * @since JJWT_RELEASE_VERSION
 */
public final class StandardHashAlgorithms implements Registry<String, HashAlgorithm> {

    private static final Registry<String, HashAlgorithm> DELEGATE =
            Classes.newInstance("io.jsonwebtoken.impl.security.StandardHashAlgorithmsBridge");

    private static final StandardHashAlgorithms INSTANCE = new StandardHashAlgorithms();

    /**
     * Returns this registry (a static singleton).
     *
     * @return this registry (a static singleton).
     */
    public static StandardHashAlgorithms get() { // named `forKey` to mimic java.util.function.Supplier
        return INSTANCE;
    }

    /**
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
     * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
     * value of {@code sha-256}. It is a {@code HashAlgorithm} alias for the native
     * Java JCA {@code SHA-256} {@code MessageDigest} algorithm.
     */
    public final HashAlgorithm SHA256 = forKey("sha-256");

    /**
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
     * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
     * value of {@code sha-384}. It is a {@code HashAlgorithm} alias for the native
     * Java JCA {@code SHA-384} {@code MessageDigest} algorithm.
     */
    public final HashAlgorithm SHA384 = forKey("sha-384");

    /**
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
     * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
     * value of {@code sha-512}. It is a {@code HashAlgorithm} alias for the native
     * Java JCA {@code SHA-512} {@code MessageDigest} algorithm.
     */
    public final HashAlgorithm SHA512 = forKey("sha-512");

    /**
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
     * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
     * value of {@code sha3-256}. It is a {@code HashAlgorithm} alias for the native
     * Java JCA {@code SHA3-256} {@code MessageDigest} algorithm.
     * <p><b>This algorithm requires at least JDK 9 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath.</b></p>
     */
    public final HashAlgorithm SHA3_256 = forKey("sha3-256");

    /**
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
     * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
     * value of {@code sha3-384}. It is a {@code HashAlgorithm} alias for the native
     * Java JCA {@code SHA3-384} {@code MessageDigest} algorithm.
     * <p><b>This algorithm requires at least JDK 9 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath.</b></p>
     */
    public final HashAlgorithm SHA3_384 = forKey("sha3-384");

    /**
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA
     * hash algorithm</a> with an {@link Identifiable#getId() id} (aka IANA &quot;{@code Hash Name String}&quot;)
     * value of {@code sha3-512}. It is a {@code HashAlgorithm} alias for the native
     * Java JCA {@code SHA3-512} {@code MessageDigest} algorithm.
     * <p><b>This algorithm requires at least JDK 9 or a compatible JCA Provider (like BouncyCastle) in the runtime
     * classpath.</b></p>
     */
    public final HashAlgorithm SHA3_512 = forKey("sha3-512");

    /**
     * Prevent external instantiation.
     */
    private StandardHashAlgorithms() {
    }

    /**
     * Returns the number (quantity) of
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
     * Algorithms</a> stored in this registry.
     *
     * @return the number (quantity) of
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
     * Algorithms</a> stored in this registry.
     */
    @Override
    public int size() {
        return DELEGATE.size();
    }

    /**
     * Returns common
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
     * Algorithms</a> as an unmodifiable collection.
     *
     * @return common
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg">IANA Hash
     * Algorithms</a> as an unmodifiable collection.
     */
    public Collection<HashAlgorithm> values() {
        return DELEGATE.values();
    }

    /**
     * Returns the {@code HashAlgorithm} instance with the specified IANA algorithm {@code id}, or throws an
     * {@link IllegalArgumentException} if there is no supported algorithm for the specified {@code id}. The
     * {@code id} parameter is expected to equal one of the string values in the <b>{@code Hash Name String}</b>
     * column within the
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml">IANA Named Information
     * Hash Algorithm Registry</a> table. If a supported instance result is not mandatory, consider using the
     * {@link Registry#get(Object)} method instead.
     *
     * @param id an IANA {@code Hash Name String} hash algorithm identifier.
     * @return the associated {@code HashAlgorithm} instance.
     * @throws IllegalArgumentException if there is no supported algorithm for the specified identifier.
     * @see Registry#get(Object)
     * @see <a href="https://www.iana.org/assignments/named-information/named-information.xhtml">IANA Named
     * Information Hash Algorithm Registry</a>
     */
    @Override
    public HashAlgorithm forKey(String id) {
        return DELEGATE.forKey(id);
    }

    /**
     * Returns the {@code HashAlgorithm} instance with the specified IANA algorithm {@code id}, or {@code null} if
     * the specified {@code id} cannot be found. The {@code id} parameter is expected to equal one of the string
     * values in the <b>{@code Hash Name String}</b> column within the
     * <a href="https://www.iana.org/assignments/named-information/named-information.xhtml">IANA Named Information
     * Hash Algorithm Registry</a> table.  If a standard instance must be resolved, consider using the
     * {@link #forKey(String)} method instead.
     *
     * @param id an IANA {@code Hash Name String} hash algorithm identifier
     * @return the associated {@code HashAlgorithm} instance if found or {@code null} otherwise.
     * @see <a href="https://www.iana.org/assignments/named-information/named-information.xhtml">IANA Named Information
     * Hash Algorithm Registry</a>
     * @see #forKey(String)
     */
    @Override
    public HashAlgorithm get(Object id) {
        return DELEGATE.get(id);
    }
}
