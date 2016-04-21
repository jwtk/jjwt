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

import static io.jsonwebtoken.lang.Arrays.clean;

public class DefaultEncryptionRequestBuilder implements EncryptionRequestBuilder {

    private SecureRandom secureRandom;
    private byte[] iv;
    private byte[] key;
    private byte[] plaintext;
    private byte[] aad;

    @Override
    public EncryptionRequestBuilder setSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
        return this;
    }

    @Override
    public EncryptionRequestBuilder setInitializationVector(byte[] iv) {
        this.iv = clean(iv);
        return this;
    }

    @Override
    public EncryptionRequestBuilder setKey(byte[] key) {
        this.key = clean(key);
        return this;
    }

    @Override
    public EncryptionRequestBuilder setPlaintext(byte[] plaintext) {
        Assert.notEmpty(plaintext, "Plaintext cannot be null or empty.");
        this.plaintext = plaintext;
        return this;
    }

    @Override
    public EncryptionRequestBuilder setAdditionalAuthenticatedData(byte[] aad) {
        this.aad = clean(aad);
        return this;
    }

    @Override
    public EncryptionRequest build() {
        Assert.notEmpty(plaintext, "Plaintext cannot be null or empty.");

        if (aad != null) {
            return new DefaultAuthenticatedEncryptionRequest(secureRandom, key, iv, plaintext, aad);
        }

        return new DefaultEncryptionRequest(secureRandom, key, iv, plaintext);
    }
}
