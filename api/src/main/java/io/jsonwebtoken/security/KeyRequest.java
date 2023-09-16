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

import io.jsonwebtoken.JweHeader;

/**
 * A request to a {@link KeyAlgorithm} to obtain the key necessary for AEAD encryption or decryption.  The exact
 * {@link AeadAlgorithm} that will be used is accessible via {@link #getEncryptionAlgorithm()}.
 *
 * <p><b>Encryption Requests</b></p>
 * <p>For an encryption key request, {@link #getPayload()} will return
 * the encryption key to use.  Additionally, any <em>public</em> information specific to the called
 * {@link KeyAlgorithm} implementation that is required to be transmitted in the JWE (such as an initialization vector,
 * authentication tag or ephemeral key, etc) may be added to the JWE protected header, accessible via
 * {@link #getHeader()}. Although the JWE header is checked for authenticity and integrity, it itself is
 * <em>not</em> encrypted, so {@link KeyAlgorithm}s should never place any secret or private information in the
 * header.</p>
 *
 * <p><b>Decryption Requests</b></p>
 * <p>For a decryption request, the {@code KeyRequest} instance will be
 * a {@link DecryptionKeyRequest} instance, {@link #getPayload()} will return the encrypted key ciphertext (a
 * byte array), and the decryption key will be available via {@link DecryptionKeyRequest#getKey()}.  Additionally,
 * any public information necessary by the called {@link KeyAlgorithm} (such as an initialization vector,
 * authentication tag, ephemeral key, etc) is expected to be available in the JWE protected header, accessible
 * via {@link #getHeader()}.</p>
 *
 * @param <T> the type of object relevant during key algorithm cryptographic operations.
 * @see DecryptionKeyRequest
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyRequest<T> extends Request<T> {

    /**
     * Returns the {@link AeadAlgorithm} that will be called for encryption or decryption after processing the
     * {@code KeyRequest}.  {@link KeyAlgorithm} implementations that generate an ephemeral {@code SecretKey} to use
     * as what the <a href="https://www.rfc-editor.org/rfc/rfc7516.html#section-2">JWE specification calls</a> a
     * &quot;Content Encryption Key (CEK)&quot; should call the {@code AeadAlgorithm}'s
     * {@link AeadAlgorithm#key() key()} builder to create a key suitable for that exact {@code AeadAlgorithm}.
     *
     * @return the {@link AeadAlgorithm} that will be called for encryption or decryption after processing the
     * {@code KeyRequest}.
     */
    AeadAlgorithm getEncryptionAlgorithm();

    /**
     * Returns the {@link JweHeader} that will be used to construct the final JWE header, available for
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
     * @return the {@link JweHeader} that will be used to construct the final JWE header, available for
     * reading or writing any {@link KeyAlgorithm}-specific information.
     */
    JweHeader getHeader();
}
