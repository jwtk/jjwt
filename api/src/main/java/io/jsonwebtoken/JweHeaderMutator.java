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

import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithms;

/**
 * Mutation (modifications) to a {@link JweHeader} instance.
 *
 * @param <T> the mutator subtype, for method chaining
 * @since JJWT_RELEASE_VERSION
 */
public interface JweHeaderMutator<T extends JweHeaderMutator<T>> extends ProtectedHeaderMutator<T> {

//    /**
//     * Sets the JWE <a href="https://tools.ietf.org/html/rfc7516#section-4.1.2">{@code enc} (Encryption
//     * Algorithm)</a> header value.  A {@code null} value will remove the property from the JSON map.
//     *
//     * <p>This should almost never be set by JJWT users directly - JJWT will always set this value to the value
//     * returned by {@link AeadAlgorithm#getId()} when performing encryption, overwriting any potential previous
//     * value.</p>
//     *
//     * @param enc the encryption algorithm identifier obtained from {@link AeadAlgorithm#getId()}.
//     * @return this header for method chaining
//     */
//    @SuppressWarnings("UnusedReturnValue")
//    JweHeader setEncryptionAlgorithm(String enc);

    /**
     * Sets any information about the JWE producer for use with key agreement algorithms. A {@code null} or empty value
     * removes the property from the JSON map.
     *
     * @param info information about the JWE producer to use with key agreement algorithms.
     * @return the header for method chaining.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.2">JWE <code>apu</code> (Agreement PartyUInfo) Header Parameter</a>
     * @see KeyAlgorithms#ECDH_ES
     * @see KeyAlgorithms#ECDH_ES_A128KW
     * @see KeyAlgorithms#ECDH_ES_A192KW
     * @see KeyAlgorithms#ECDH_ES_A256KW
     */
    T setAgreementPartyUInfo(byte[] info);

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
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.2">JWE <code>apu</code> (Agreement PartyUInfo) Header Parameter</a>
     * @see KeyAlgorithms#ECDH_ES
     * @see KeyAlgorithms#ECDH_ES_A128KW
     * @see KeyAlgorithms#ECDH_ES_A192KW
     * @see KeyAlgorithms#ECDH_ES_A256KW
     */
    T setAgreementPartyUInfo(String info);

    /**
     * Sets any information about the JWE recipient for use with key agreement algorithms. A {@code null} value removes
     * the property from the JSON map.
     *
     * @param info information about the JWE recipient to use with key agreement algorithms.
     * @return the header for method chaining.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.3">JWE <code>apv</code> (Agreement PartyVInfo) Header Parameter</a>
     * @see KeyAlgorithms#ECDH_ES
     * @see KeyAlgorithms#ECDH_ES_A128KW
     * @see KeyAlgorithms#ECDH_ES_A192KW
     * @see KeyAlgorithms#ECDH_ES_A256KW
     */
    T setAgreementPartyVInfo(byte[] info);

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
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.3">JWE <code>apv</code> (Agreement PartyVInfo) Header Parameter</a>
     * @see KeyAlgorithms#ECDH_ES
     * @see KeyAlgorithms#ECDH_ES_A128KW
     * @see KeyAlgorithms#ECDH_ES_A192KW
     * @see KeyAlgorithms#ECDH_ES_A256KW
     */
    T setAgreementPartyVInfo(String info);

    /**
     * Sets the number of PBKDF2 iterations necessary to derive the key used during JWE encryption. If this value
     * is not set when a password-based {@link KeyAlgorithm} is used, JJWT will automatically choose a suitable
     * number of iterations based on
     * <a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2">OWASP PBKDF2 Iteration Recommendations</a>.
     *
     * <p><b>Minimum Count</b></p>
     *
     * <p>{@code IllegalArgumentException} will be thrown during encryption if a specified {@code count} is
     * less than 1000 (one thousand), which is the
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.2">minimum number recommended</a> by the
     * JWA specification. Anything less is susceptible to security attacks so the default PBKDF2
     * {@code KeyAlgorithm} implementations reject such values.</p>
     *
     * @param count the number of PBKDF2 iterations necessary to derive the key used during JWE encryption, must be
     *              greater than or equal to 1000 (one thousand).
     * @return the header for method chaining
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.2">JWE <code>p2c</code> (PBES2 Count) Header Parameter</a>
     * @see KeyAlgorithms#PBES2_HS256_A128KW
     * @see KeyAlgorithms#PBES2_HS384_A192KW
     * @see KeyAlgorithms#PBES2_HS512_A256KW
     * @see <a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2">OWASP PBKDF2 Iteration Recommendations</a>
     */
    T setPbes2Count(int count);

//    /**
//     * Sets the PBKDF2 {@code Salt Input} value necessary to derive the key used during JWE encryption. This should
//     * almost never be used by JJWT users directly - it should instead be automatically generated and set within a
//     * PBKDF2-based {@link io.jsonwebtoken.security.KeyAlgorithm KeyAlgorithm} implementation.
//     *
//     * @param salt the PBKDF2 {@code Salt Input} value necessary to derive the key used during JWE encryption.
//     * @return the header for method chaining
//     * @see <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8.1.1">JWE <code>p2s</code> (PBES2 Salt Input) Header Parameter</a>
//     * @see KeyAlgorithms#PBES2_HS256_A128KW
//     * @see KeyAlgorithms#PBES2_HS384_A192KW
//     * @see KeyAlgorithms#PBES2_HS512_A256KW
//     */
//    JweHeader setPbes2Salt(byte[] salt);

}
