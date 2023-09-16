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
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.security.Key;

/**
 * A {@code KeyAlgorithm} produces the {@link SecretKey} used to encrypt or decrypt a JWE. The {@code KeyAlgorithm}
 * used for a particular JWE is {@link #getId() identified} in the JWE's
 * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1">{@code alg} header</a>.  The {@code KeyAlgorithm}
 * interface is JJWT's idiomatic approach to the JWE specification's
 * <a href="https://tools.ietf.org/html/rfc7516#section-2">{@code Key Management Mode}</a> concept.
 *
 * <p>All standard Key Algorithms are defined in
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1">JWA (RFC 7518), Section 4.1</a>,
 * and they are all available as concrete instances via {@link Jwts.KEY}.</p>
 *
 * <p><b>&quot;alg&quot; identifier</b></p>
 *
 * <p>{@code KeyAlgorithm} extends {@code Identifiable}: the value returned from
 * {@link Identifiable#getId() keyAlgorithm.getId()} will be used as the
 * <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1">JWE &quot;alg&quot; protected header</a> value.</p>
 *
 * @param <E> The type of key to use to obtain the AEAD encryption key
 * @param <D> The type of key to use to obtain the AEAD decryption key
 * @see Jwts.KEY
 * @see <a href="https://tools.ietf.org/html/rfc7516#section-2">RFC 7561, Section 2: JWE Key (Management) Algorithms</a>
 * @since JJWT_RELEASE_VERSION
 */
@SuppressWarnings("JavadocLinkAsPlainText")
public interface KeyAlgorithm<E extends Key, D extends Key> extends Identifiable {

    /**
     * Return the {@link SecretKey} that should be used to encrypt a JWE via the request's specified
     * {@link KeyRequest#getEncryptionAlgorithm() AeadAlgorithm}.  The encryption key will
     * be available via the result's {@link KeyResult#getKey() result.getKey()} method.
     *
     * <p>If the key algorithm uses key encryption or key agreement to produce an encrypted key value that must be
     * included in the JWE, the encrypted key ciphertext will be available via the result's
     * {@link KeyResult#getPayload() result.getPayload()} method.  If the key algorithm does not produce encrypted
     * key ciphertext, {@link KeyResult#getPayload() result.getPayload()} will be a non-null empty byte array.</p>
     *
     * @param request the {@code KeyRequest} containing information necessary to produce a {@code SecretKey} for
     *                {@link AeadAlgorithm AEAD} encryption.
     * @return the {@link SecretKey} that should be used to encrypt a JWE via the request's specified
     * {@link KeyRequest#getEncryptionAlgorithm() AeadAlgorithm}, along with any optional encrypted key ciphertext.
     * @throws SecurityException if there is a problem obtaining or encrypting the AEAD {@code SecretKey}.
     */
    KeyResult getEncryptionKey(KeyRequest<E> request) throws SecurityException;

    /**
     * Return the {@link SecretKey} that should be used to decrypt a JWE via the request's specified
     * {@link DecryptionKeyRequest#getEncryptionAlgorithm() AeadAlgorithm}.
     *
     * <p>If the key algorithm used key encryption or key agreement to produce an encrypted key value, the encrypted
     * key ciphertext will be available via the request's {@link DecryptionKeyRequest#getPayload() result.getPayload()}
     * method. If the key algorithm did not produce encrypted key ciphertext,
     * {@link DecryptionKeyRequest#getPayload() request.getPayload()} will return a non-null empty byte array.</p>
     *
     * @param request the {@code DecryptionKeyRequest} containing information necessary to obtain a
     *                {@code SecretKey} for {@link AeadAlgorithm AEAD} decryption.
     * @return the {@link SecretKey} that should be used to decrypt a JWE via the request's specified
     * {@link DecryptionKeyRequest#getEncryptionAlgorithm() AeadAlgorithm}.
     * @throws SecurityException if there is a problem obtaining or decrypting the AEAD {@code SecretKey}.
     */
    SecretKey getDecryptionKey(DecryptionKeyRequest<D> request) throws SecurityException;
}
