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

import io.jsonwebtoken.lang.Assert;

import java.security.SecureRandom;

public class DefaultEncryptionRequest extends AbstractCryptoRequest implements EncryptionRequest {

    private final SecureRandom random;

    private final byte[] plaintext;

    public DefaultEncryptionRequest(SecureRandom secureRandom, byte[] key, byte[] iv, byte[] plaintext) {
        super(key, iv);
        Assert.notEmpty(plaintext, "plaintext cannot be null or empty.");
        this.plaintext = plaintext;
        this.random = secureRandom;
    }

    @Override
    public SecureRandom getSecureRandom() {
        return this.random;
    }

    @Override
    public byte[] getPlaintext() {
        return this.plaintext;
    }
}
