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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.DecryptionKeyRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultDecryptionKeyRequest<K extends Key> extends DefaultKeyRequest<byte[]> implements DecryptionKeyRequest<K> {

    private final K decryptionKey;

    public DefaultDecryptionKeyRequest(byte[] encryptedCek, Provider provider, SecureRandom secureRandom,
                                       JweHeader header, AeadAlgorithm encryptionAlgorithm, K decryptionKey) {
        super(encryptedCek, provider, secureRandom, header, encryptionAlgorithm);
        this.decryptionKey = Assert.notNull(decryptionKey, "decryption key cannot be null.");
    }

    @Override
    protected void assertBytePayload(byte[] payload) {
        Assert.notNull(payload, "encrypted key bytes cannot be null (but may be empty.");
    }

    @Override
    public K getKey() {
        return this.decryptionKey;
    }
}
