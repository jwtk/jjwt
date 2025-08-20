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

import javax.crypto.SecretKey;

/**
 * A request to an {@link AeadAlgorithm} to decrypt ciphertext with integrity verification with a supplied
 * decryption {@link SecretKey}. Extends both {@link IvSupplier} and {@link DigestSupplier} to
 * ensure the respective required IV and AAD tag returned from an {@link AeadResult} are available for decryption.
 *
 * @since 0.12.0
 */
public interface DecryptAeadRequest extends AeadRequest, IvSupplier, DigestSupplier {

    /**
     * Named parameters (setters) used to configure an {@link AeadRequest AeadRequest} instance.
     *
     * @since 0.13.0
     */
    interface Params<M extends Params<M>> extends AeadRequest.Params<M> {

        /**
         * Sets the required initialization vector used during AEAD decryption.
         *
         * @param iv the required initialization vector used during AEAD decryption.
         */
        M iv(byte[] iv);

        /**
         * Sets the required AEAD Authentication Tag used to verify message authenticity during AEAD decryption.
         *
         * @param digest the required AEAD Authentication Tag used to verify message authenticity during AEAD decryption.
         * @return the instance for method chaining.
         */
        M digest(byte[] digest);
    }

    /**
     * A builder for creating new immutable {@link DecryptAeadRequest} instances.
     *
     * @since 0.13.0
     */
    interface Builder extends io.jsonwebtoken.lang.Builder<DecryptAeadRequest>, Params<Builder> {
    }

}
