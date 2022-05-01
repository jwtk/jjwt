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

    Integer getPbes2Count();

    JweHeader setPbes2Count(int count);

    byte[] getPbes2Salt();

    JweHeader setPbes2Salt(byte[] salt);

    byte[] getAgreementPartyUInfo();

    String getAgreementPartyUInfoString();

    JweHeader setAgreementPartyUInfo(byte[] info);

    JweHeader setAgreementPartyUInfo(String info);

    byte[] getAgreementPartyVInfo();

    String getAgreementPartyVInfoString();

    JweHeader setAgreementPartyVInfo(byte[] info);

    JweHeader setAgreementPartyVInfo(String info);
}
