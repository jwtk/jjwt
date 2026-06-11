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
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.lang.Assert;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.function.Consumer;

/**
 * A {@code KeyAlgorithm} produces the {@link SecretKey} used to encrypt or decrypt a JWE. The {@code KeyAlgorithm}
 * used for a particular JWE is {@link #getId() identified} in the JWE's
 * <a href="https://tools.ietf.org/html/rfc7516#section-4.1.1">{@code alg} header</a>.  The {@code KeyAlgorithm}
 * interface is JJWT's idiomatic approach to the JWE specification's
 * <a href="https://tools.ietf.org/html/rfc7516#section-2">{@code Key Management Mode}</a> concept.
 *
 * <p>All standard Key Algorithms are defined in
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1">JWA (RFC 7518), Section 4.1</a>,
 * and they are all available as concrete instances via {@link io.jsonwebtoken.Jwe.enc Jwe.enc}.</p>
 *
 * <p><b>&quot;alg&quot; identifier</b></p>
 *
 * <p>{@code KeyAlgorithm} extends {@code Identifiable}: the value returned from
 * {@link Identifiable#getId() keyAlgorithm.getId()} will be used as the
 * <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1">JWE &quot;alg&quot; protected header</a> value.</p>
 *
 * @param <E> The type of key to use to obtain the AEAD encryption key
 * @param <D> The type of key to use to obtain the AEAD decryption key
 * @see io.jsonwebtoken.Jwe.enc Jwe.enc
 * @see <a href="https://tools.ietf.org/html/rfc7516#section-2">RFC 7561, Section 2: JWE Key (Management) Algorithms</a>
 * @since 0.12.0
 */
@SuppressWarnings("JavadocLinkAsPlainText")
public interface KeyAlgorithm<E extends Key, D extends Key> extends Identifiable {

    /**
     * Named parameters used to obtain an encryption or decryption key.
     *
     * @param <T> the type of payload. For an encryption key request, this will be the
     *            key used to obtain the encryption key. For a decryption key request, this will be the encrypted CEK
     *            (Content Encryption Key) ciphertext byte array.
     * @param <P> the instance type returned for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    interface Params<T, P extends Params<T, P>> extends PayloadParams<T, P> {

        /**
         * Sets the {@link JweHeader} that will be used to construct the final JWE header, available for
         * reading or writing any {@link KeyAlgorithm}-specific information.
         *
         * <p>For an encryption key request, any <em>public</em> information specific to the called {@code KeyAlgorithm}
         * implementation that is required to be transmitted in the JWE (such as an initialization vector,
         * authentication tag or ephemeral key, etc) is expected to be added to this header. Although the header is
         * checked for authenticity and integrity, it itself is <em>not</em> encrypted, so
         * {@link KeyAlgorithm}s should never place any secret or private information in the header.</p>
         *
         * <p>For a decryption request, any public information necessary by the called {@link KeyAlgorithm}
         * (such as an initialization vector, authentication tag, ephemeral key, etc) is expected to be available in
         * this header.</p>
         *
         * @param header the {@link JweHeader} that will be used to construct the final JWE header, available for
         *               reading or writing any {@link KeyAlgorithm}-specific information.
         * @return the instance for method chaining.
         */
        P header(JweHeader header);

        /**
         * Sets the {@link AeadAlgorithm} that will be called for encryption or decryption after processing the
         * {@code KeyRequest}. {@link KeyAlgorithm} implementations that generate an ephemeral {@code SecretKey} to use
         * as what the <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-2">JWE specification calls</a> a
         * &quot;Content Encryption Key (CEK)&quot; should call the {@code AeadAlgorithm}'s
         * {@link AeadAlgorithm#key() key()} builder to create a key suitable for that exact {@code AeadAlgorithm}.
         *
         * @param alg the {@link AeadAlgorithm} that will be called for encryption or decryption after processing the
         *            {@code KeyRequest}.
         * @return the instance for method chaining.
         */
        P encryptionAlgorithm(AeadAlgorithm alg);
    }

    /**
     * Named parameters used to obtain a decryption key.
     *
     * @param <K> the type of key used by the {@link KeyAlgorithm} to obtain the JWE Content Encryption Key (CEK).
     * @param <P> the instance type returned for method chaining.
     * @since JJWT_RELEASE_VERSION
     */
    interface DecryptParams<K extends Key, P extends DecryptParams<K, P>> extends Params<byte[], P>, Keyable<K, P> {
    }

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

    default KeyResult getEncryptionKey(Consumer<Params<E, ?>> p) throws SecurityException {
        Assert.notNull(p, "Consumer cannot be null");
        KeyRequest.Builder<E> builder = KeyRequest.builder();
        p.accept(builder);
        return getEncryptionKey(builder.build());
    }

    default KeyResult getEncryptionKey(E key, JweHeader header, AeadAlgorithm enc) throws SecurityException {
        return getEncryptionKey(p -> p.payload(key).header(header).encryptionAlgorithm(enc));
    }

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

    default SecretKey getDecryptionKey(Consumer<DecryptParams<D, ?>> p) throws SecurityException {
        Assert.notNull(p, "Consumer cannot be null");
        DecryptionKeyRequest.Builder<D> builder = DecryptionKeyRequest.builder();
        p.accept(builder);
        return getDecryptionKey(builder.build());
    }

    default SecretKey getDecryptionKey(byte[] cekCiphertext, D decryptionKey, JweHeader header, AeadAlgorithm enc) throws SecurityException {
        return getDecryptionKey(p -> p.payload(cekCiphertext).key(decryptionKey).header(header).encryptionAlgorithm(enc));
    }
}
