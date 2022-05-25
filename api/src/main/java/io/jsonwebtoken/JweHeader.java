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

import io.jsonwebtoken.security.KeyAlgorithms;

/**
 * A <a href="https://tools.ietf.org/html/rfc7516">JWE</a> header.
 *
 * @since JJWT_RELEASE_VERSION
 */
public interface JweHeader extends ProtectedHeader<JweHeader> {

    /**
     * Returns the JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.2">{@code enc}</a> (Encryption
     * Algorithm) header value or {@code null} if not present.
     *
     * <p>The JWE {@code enc} (encryption algorithm) Header Parameter identifies the content encryption algorithm
     * used to perform authenticated encryption on the plaintext to produce the ciphertext and the JWE
     * {@code Authentication Tag}.</p>
     *
     * @return the JWE {@code enc} (Encryption Algorithm) header value or {@code null} if not present.  This will
     * always be {@code non-null} on validly-constructed JWE instances, but could be {@code null} during construction.
     */
    String getEncryptionAlgorithm();

    //commented out on purpose - API users shouldn't call this method as it is always called by the Jwt/Jwe Builder
//    /**
//     * Sets the JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.2"><code>enc</code></a> (Encryption
//     * Algorithm) header value.  A {@code null} value will remove the property from the JSON map.
//     * <p>The JWE {@code enc} (encryption algorithm) Header Parameter identifies the content encryption algorithm
//     * used to perform authenticated encryption on the plaintext to produce the ciphertext and the JWE
//     * {@code Authentication Tag}.</p>
//     *
//     * @param enc the encryption algorithm identifier
//     * @return this header for method chaining
//     */
//    JweHeader setEncryptionAlgorithm(String enc);

    /**
     * Returns the number of PBKDF2 iterations necessary to derive the key used to encrypt the JWE, or {@code null}
     * if not present. Used with password-based {@link io.jsonwebtoken.security.KeyAlgorithm KeyAlgorithm}s.
     *
     * @return the number of PBKDF2 iterations necessary to derive the key used to encrypt the JWE, or {@code null}
     * if not present.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.2">JWE <code>p2c</code> (PBES2 Count) Header Parameter</a>
     * @see KeyAlgorithms#PBES2_HS256_A128KW
     * @see KeyAlgorithms#PBES2_HS384_A192KW
     * @see KeyAlgorithms#PBES2_HS512_A256KW
     */
    Integer getPbes2Count();

    /**
     * Sets the number of PBKDF2 iterations necessary to derive the key used to encrypt the JWE.  A {@code null} value
     * will remove the property from the JSON map.
     *
     * @param count the number of PBKDF2 iterations necessary to derive the key used to encrypt the JWE.
     * @return the header for method chaining
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.2">JWE <code>p2c</code> (PBES2 Count) Header Parameter</a>
     * @see KeyAlgorithms#PBES2_HS256_A128KW
     * @see KeyAlgorithms#PBES2_HS384_A192KW
     * @see KeyAlgorithms#PBES2_HS512_A256KW
     */
    JweHeader setPbes2Count(int count);

    /**
     * Returns the PBKDF2 {@code Salt Input} value necessary to derive the key used to encrypt the JWE, or {@code null}
     * if not present. Used with password-based {@link io.jsonwebtoken.security.KeyAlgorithm KeyAlgorithm}s.
     *
     * @return the PBKDF2 {@code Salt Input} value necessary to derive the key used to encrypt the JWE, or {@code null}
     * if not present.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.1">JWE <code>p2s</code> (PBES2 Salt Input) Header Parameter</a>
     * @see KeyAlgorithms#PBES2_HS256_A128KW
     * @see KeyAlgorithms#PBES2_HS384_A192KW
     * @see KeyAlgorithms#PBES2_HS512_A256KW
     */
    byte[] getPbes2Salt();

    /**
     * Sets the PBKDF2 {@code Salt Input} value necessary to derive the key used to encrypt the JWE.  This should
     * almost never be used by JJWT users directly - it should be automatically generated and set within a PBKDF2-based
     * {@link io.jsonwebtoken.security.KeyAlgorithm KeyAlgorithm} implementation.
     *
     * @param salt the PBKDF2 {@code Salt Input} value necessary to derive the key used to encrypt the JWE.
     * @return the header for method chaining
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.1">JWE <code>p2s</code> (PBES2 Salt Input) Header Parameter</a>
     * @see KeyAlgorithms#PBES2_HS256_A128KW
     * @see KeyAlgorithms#PBES2_HS384_A192KW
     * @see KeyAlgorithms#PBES2_HS512_A256KW
     */
    JweHeader setPbes2Salt(byte[] salt);

    /**
     * Returns any information about the JWE producer for use with key agreement algorithms, or {@code null} if not
     * present.
     *
     * @return any information about the JWE producer for use with key agreement algorithms, or {@code null} if not
     * present.
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.2">JWE <code>apu</code> (Agreement PartyUInfo) Header Parameter</a>
     * @see KeyAlgorithms#ECDH_ES
     * @see KeyAlgorithms#ECDH_ES_A128KW
     * @see KeyAlgorithms#ECDH_ES_A192KW
     * @see KeyAlgorithms#ECDH_ES_A256KW
     */
    byte[] getAgreementPartyUInfo();

    /**
     * Returns any information about the JWE producer for use with key agreement algorithms as a UTF-8 String,
     * or {@code null} if not present.
     *
     * <p>If not {@code null}, this is a convenience method that returns the equivalent of the following:</p>
     * <blockquote><pre>
     * new String({@link #getAgreementPartyUInfo() getAgreementPartyUInfo()}, StandardCharsets.UTF_8)</pre></blockquote>
     *
     * @return any information about the JWE producer for use with key agreement algorithms, or {@code null} if not
     * present.
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.2">JWE <code>apu</code> (Agreement PartyUInfo) Header Parameter</a>
     * @see KeyAlgorithms#ECDH_ES
     * @see KeyAlgorithms#ECDH_ES_A128KW
     * @see KeyAlgorithms#ECDH_ES_A192KW
     * @see KeyAlgorithms#ECDH_ES_A256KW
     */
    String getAgreementPartyUInfoString();

    /**
     * Sets any information about the JWE producer for use with key agreement algorithms. A {@code null} value removes
     * the property from the JSON map.
     *
     * @param info information about the JWE producer to use with key agreement algorithms.
     * @return the header for method chaining.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.2">JWE <code>apu</code> (Agreement PartyUInfo) Header Parameter</a>
     * @see KeyAlgorithms#ECDH_ES
     * @see KeyAlgorithms#ECDH_ES_A128KW
     * @see KeyAlgorithms#ECDH_ES_A192KW
     * @see KeyAlgorithms#ECDH_ES_A256KW
     */
    JweHeader setAgreementPartyUInfo(byte[] info);

    /**
     * Sets any information about the JWE producer for use with key agreement algorithms. A {@code null} value removes
     * the property from the JSON map.
     *
     * <p>If not {@code null}, this is a convenience method that calls the equivalent of the following:</p>
     * <blockquote><pre>
     * {@link #setAgreementPartyUInfo(byte[]) setAgreementPartyUInfo}(info.getBytes(StandardCharsets.UTF_8))</pre></blockquote>
     *
     * @param info information about the JWE producer to use with key agreement algorithms.
     * @return the header for method chaining.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.2">JWE <code>apu</code> (Agreement PartyUInfo) Header Parameter</a>
     * @see KeyAlgorithms#ECDH_ES
     * @see KeyAlgorithms#ECDH_ES_A128KW
     * @see KeyAlgorithms#ECDH_ES_A192KW
     * @see KeyAlgorithms#ECDH_ES_A256KW
     */
    JweHeader setAgreementPartyUInfo(String info);

    /**
     * Returns any information about the JWE recipient for use with key agreement algorithms, or {@code null} if not
     * present.
     *
     * @return any information about the JWE recipient for use with key agreement algorithms, or {@code null} if not
     * present.
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.3">JWE <code>apv</code> (Agreement PartyVInfo) Header Parameter</a>
     * @see KeyAlgorithms#ECDH_ES
     * @see KeyAlgorithms#ECDH_ES_A128KW
     * @see KeyAlgorithms#ECDH_ES_A192KW
     * @see KeyAlgorithms#ECDH_ES_A256KW
     */
    byte[] getAgreementPartyVInfo();

    /**
     * Returns any information about the JWE recipient for use with key agreement algorithms as a UTF-8 String,
     * or {@code null} if not present.
     *
     * <p>If not {@code null}, this is a convenience method that returns the equivalent of the following:</p>
     * <blockquote><pre>
     * new String({@link #getAgreementPartyVInfo() getAgreementPartyVInfo()}, StandardCharsets.UTF_8)</pre></blockquote>
     *
     * @return any information about the JWE recipient for use with key agreement algorithms, or {@code null} if not
     * present.
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.3">JWE <code>apv</code> (Agreement PartyVInfo) Header Parameter</a>
     * @see KeyAlgorithms#ECDH_ES
     * @see KeyAlgorithms#ECDH_ES_A128KW
     * @see KeyAlgorithms#ECDH_ES_A192KW
     * @see KeyAlgorithms#ECDH_ES_A256KW
     */
    String getAgreementPartyVInfoString();

    /**
     * Sets any information about the JWE recipient for use with key agreement algorithms. A {@code null} value removes
     * the property from the JSON map.
     *
     * @param info information about the JWE recipient to use with key agreement algorithms.
     * @return the header for method chaining.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.3">JWE <code>apv</code> (Agreement PartyVInfo) Header Parameter</a>
     * @see KeyAlgorithms#ECDH_ES
     * @see KeyAlgorithms#ECDH_ES_A128KW
     * @see KeyAlgorithms#ECDH_ES_A192KW
     * @see KeyAlgorithms#ECDH_ES_A256KW
     */
    JweHeader setAgreementPartyVInfo(byte[] info);

    /**
     * Sets any information about the JWE recipient for use with key agreement algorithms. A {@code null} value removes
     * the property from the JSON map.
     *
     * <p>If not {@code null}, this is a convenience method that calls the equivalent of the following:</p>
     * <blockquote><pre>
     * {@link #setAgreementPartyVInfo(byte[]) setAgreementPartVUInfo}(info.getBytes(StandardCharsets.UTF_8))</pre></blockquote>
     *
     * @param info information about the JWE recipient to use with key agreement algorithms.
     * @return the header for method chaining.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.3">JWE <code>apv</code> (Agreement PartyVInfo) Header Parameter</a>
     * @see KeyAlgorithms#ECDH_ES
     * @see KeyAlgorithms#ECDH_ES_A128KW
     * @see KeyAlgorithms#ECDH_ES_A192KW
     * @see KeyAlgorithms#ECDH_ES_A256KW
     */
    JweHeader setAgreementPartyVInfo(String info);
}
