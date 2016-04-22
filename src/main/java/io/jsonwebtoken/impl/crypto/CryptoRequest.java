/*
 * Copyright (C) 2016 jsonwebtoken.io
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
package io.jsonwebtoken.impl.crypto;

/**
 * @since 0.7.0
 */
public interface CryptoRequest {

    /**
     * Returns the key to use for encryption or decryption depending on the type of request.
     *
     * @return the key to use for encryption or decryption depending on the type of request.
     */
    byte[] getKey();

    /**
     * Returns the initialization vector to use during encryption or decryption depending on the type of request.
     * <p>
     * <p>If this value is {@code null} on an {@link EncryptionRequest}, a default initialization vector will be
     * auto-generated, as it is never safe to use most cryptographic algorithms without initialization vectors
     * (such as AES).</p>
     * <p>
     * <p>This implies that all decryption requests must always supply an initialization vector since encryption
     * will always have one.</p>
     *
     * @return the initialization vector to use during encryption or decryption depending on the type of request.
     */
    byte[] getInitializationVector();

}