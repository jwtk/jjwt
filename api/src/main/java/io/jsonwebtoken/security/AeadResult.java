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

import java.io.OutputStream;

/**
 * The result of authenticated encryption, providing access to the ciphertext {@link #getOutputStream() output stream}
 * and resulting {@link #setTag(byte[]) AAD tag} and {@link #setIv(byte[]) initialization vector}.
 * The AAD tag and initialization vector must be supplied with the ciphertext to decrypt.
 *
 * @since 0.12.0
 */
public interface AeadResult {

    /**
     * Returns the {@code OutputStream} the AeadAlgorithm will use to write the resulting ciphertext during
     * encryption or plaintext during decryption.
     *
     * @return the {@code OutputStream} the AeadAlgorithm will use to write the resulting ciphertext during
     * encryption or plaintext during decryption.
     */
    OutputStream getOutputStream();

    /**
     * Sets the AEAD authentication tag.
     *
     * @param tag the AEAD authentication tag.
     * @return the AeadResult for method chaining.
     */
    AeadResult setTag(byte[] tag);

    /**
     * Sets the initialization vector used during encryption.
     *
     * @param iv the initialization vector used during encryption.
     * @return the AeadResult for method chaining.
     */
    AeadResult setIv(byte[] iv);
}
