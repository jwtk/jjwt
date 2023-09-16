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
package io.jsonwebtoken;

import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.PublicJwk;

import javax.crypto.SecretKey;
import java.security.Key;

/**
 * A <a href="https://www.rfc-editor.org/rfc/rfc7516.html">JWE</a> header.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface JweHeader extends ProtectedHeader {

    /**
     * Returns the JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.2">{@code enc} (Encryption
     * Algorithm)</a> header value or {@code null} if not present.
     *
     * <p>The JWE {@code enc} (encryption algorithm) Header Parameter identifies the content encryption algorithm
     * used to perform authenticated encryption on the plaintext to produce the ciphertext and the JWE
     * {@code Authentication Tag}.</p>
     *
     * <p>Note that there is no corresponding 'setter' method for this 'getter' because JJWT users set this value by
     * supplying an {@link AeadAlgorithm} to a {@link JwtBuilder} via one of its
     * {@link JwtBuilder#encryptWith(SecretKey, AeadAlgorithm) encryptWith(SecretKey, AeadAlgorithm)} or
     * {@link JwtBuilder#encryptWith(Key, KeyAlgorithm, AeadAlgorithm) encryptWith(Key, KeyAlgorithm, AeadAlgorithm)}
     * methods. JJWT will then set this {@code enc} header value automatically to the {@code AeadAlgorithm}'s
     * {@link AeadAlgorithm#getId() getId()} value during encryption.</p>
     *
     * @return the JWE {@code enc} (Encryption Algorithm) header value or {@code null} if not present.  This will
     * always be {@code non-null} on validly-constructed JWE instances, but could be {@code null} during construction.
     * @see JwtBuilder#encryptWith(SecretKey, AeadAlgorithm)
     * @see JwtBuilder#encryptWith(Key, KeyAlgorithm, AeadAlgorithm)
     */
    String getEncryptionAlgorithm();

    /**
     * Returns the <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1">{@code epk} (Ephemeral
     * Public Key)</a> header value created by the JWE originator for use with key agreement algorithms, or
     * {@code null} if not present.
     *
     * <p>Note that there is no corresponding 'setter' method for this 'getter' because JJWT users set this value by
     * supplying an ECDH-ES {@link KeyAlgorithm} to a {@link JwtBuilder} via its
     * {@link JwtBuilder#encryptWith(Key, KeyAlgorithm, AeadAlgorithm) encryptWith(Key, KeyAlgorithm, AeadAlgorithm)}
     * method. The ECDH-ES {@code KeyAlgorithm} implementation will then set this {@code epk} header value
     * automatically when producing the encryption key.</p>
     *
     * @return the <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1">{@code epk} (Ephemeral
     * Public Key)</a> header value created by the JWE originator for use with key agreement algorithms, or
     * {@code null} if not present.
     * @see Jwts.KEY
     * @see Jwts.KEY#ECDH_ES
     * @see Jwts.KEY#ECDH_ES_A128KW
     * @see Jwts.KEY#ECDH_ES_A192KW
     * @see Jwts.KEY#ECDH_ES_A256KW
     */
    PublicJwk<?> getEphemeralPublicKey();

    /**
     * Returns any information about the JWE producer for use with key agreement algorithms, or {@code null} if not
     * present.
     *
     * @return any information about the JWE producer for use with key agreement algorithms, or {@code null} if not
     * present.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.2">JWE <code>apu</code> (Agreement PartyUInfo) Header Parameter</a>
     * @see Jwts.KEY#ECDH_ES
     * @see Jwts.KEY#ECDH_ES_A128KW
     * @see Jwts.KEY#ECDH_ES_A192KW
     * @see Jwts.KEY#ECDH_ES_A256KW
     */
    byte[] getAgreementPartyUInfo();

    /**
     * Returns any information about the JWE recipient for use with key agreement algorithms, or {@code null} if not
     * present.
     *
     * @return any information about the JWE recipient for use with key agreement algorithms, or {@code null} if not
     * present.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.3">JWE <code>apv</code> (Agreement PartyVInfo) Header Parameter</a>
     * @see Jwts.KEY#ECDH_ES
     * @see Jwts.KEY#ECDH_ES_A128KW
     * @see Jwts.KEY#ECDH_ES_A192KW
     * @see Jwts.KEY#ECDH_ES_A256KW
     */
    byte[] getAgreementPartyVInfo();

    /**
     * Returns the 96-bit <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.1">&quot;iv&quot;
     * (Initialization Vector)</a> generated during key encryption, or {@code null} if not present.
     * Set by AES GCM {@link io.jsonwebtoken.security.KeyAlgorithm KeyAlgorithm} implementations.
     *
     * <p>Note that there is no corresponding 'setter' method for this 'getter' because JJWT users set this value by
     * supplying an AES GCM Wrap {@link KeyAlgorithm} to a {@link JwtBuilder} via its
     * {@link JwtBuilder#encryptWith(Key, KeyAlgorithm, AeadAlgorithm) encryptWith(Key, KeyAlgorithm, AeadAlgorithm)}
     * method. The AES GCM Wrap {@code KeyAlgorithm} implementation will then set this {@code iv} header value
     * automatically when producing the encryption key.</p>
     *
     * @return the 96-bit initialization vector generated during key encryption, or {@code null} if not present.
     * @see Jwts.KEY#A128GCMKW
     * @see Jwts.KEY#A192GCMKW
     * @see Jwts.KEY#A256GCMKW
     */
    byte[] getInitializationVector();

    /**
     * Returns the 128-bit <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7.1.2">&quot;tag&quot;
     * (Authentication Tag)</a> resulting from key encryption, or {@code null} if not present.
     *
     * <p>Note that there is no corresponding 'setter' method for this 'getter' because JJWT users set this value by
     * supplying an AES GCM Wrap {@link KeyAlgorithm} to a {@link JwtBuilder} via its
     * {@link JwtBuilder#encryptWith(Key, KeyAlgorithm, AeadAlgorithm) encryptWith(Key, KeyAlgorithm, AeadAlgorithm)}
     * method. The AES GCM Wrap {@code KeyAlgorithm} implementation will then set this {@code tag} header value
     * automatically when producing the encryption key.</p>
     *
     * @return the 128-bit authentication tag resulting from key encryption, or {@code null} if not present.
     * @see Jwts.KEY#A128GCMKW
     * @see Jwts.KEY#A192GCMKW
     * @see Jwts.KEY#A256GCMKW
     */
    byte[] getAuthenticationTag();

    /**
     * Returns the number of PBKDF2 iterations necessary to derive the key used during JWE encryption, or {@code null}
     * if not present. Used with password-based {@link io.jsonwebtoken.security.KeyAlgorithm KeyAlgorithm}s.
     *
     * @return the number of PBKDF2 iterations necessary to derive the key used during JWE encryption, or {@code null}
     * if not present.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.2">JWE <code>p2c</code> (PBES2 Count) Header Parameter</a>
     * @see Jwts.KEY#PBES2_HS256_A128KW
     * @see Jwts.KEY#PBES2_HS384_A192KW
     * @see Jwts.KEY#PBES2_HS512_A256KW
     */
    Integer getPbes2Count();

    /**
     * Returns the PBKDF2 {@code Salt Input} value necessary to derive the key used during JWE encryption, or
     * {@code null} if not present.
     *
     * <p>Note that there is no corresponding 'setter' method for this 'getter' because JJWT users set this value by
     * supplying a password-based {@link KeyAlgorithm} to a {@link JwtBuilder} via its
     * {@link JwtBuilder#encryptWith(Key, KeyAlgorithm, AeadAlgorithm) encryptWith(Key, KeyAlgorithm, AeadAlgorithm)}
     * method. The password-based {@code KeyAlgorithm} implementation will then set this {@code p2s} header value
     * automatically when producing the encryption key.</p>
     *
     * @return the PBKDF2 {@code Salt Input} value necessary to derive the key used during JWE encryption, or
     * {@code null} if not present.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.1">JWE <code>p2s</code> (PBES2 Salt Input) Header Parameter</a>
     * @see Jwts.KEY#PBES2_HS256_A128KW
     * @see Jwts.KEY#PBES2_HS384_A192KW
     * @see Jwts.KEY#PBES2_HS512_A256KW
     */
    byte[] getPbes2Salt();
}
