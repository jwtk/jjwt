/*
 * Copyright (C) 2022 jsonwebtoken.io
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

import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyResult;

import javax.crypto.SecretKey;

public class DefaultKeyResult extends DefaultMessage<byte[]> implements KeyResult {

    private final SecretKey key;

    public DefaultKeyResult(SecretKey key) {
        this(key, Bytes.EMPTY);
    }

    public DefaultKeyResult(SecretKey key, byte[] encryptedKey) {
        super(encryptedKey);
        this.key = Assert.notNull(key, "Content Encryption Key cannot be null.");
    }

    @Override
    protected void assertBytePayload(byte[] payload) {
        Assert.notNull(payload, "encrypted key bytes cannot be null (but may be empty.");
    }

    @Override
    public SecretKey getKey() {
        return this.key;
    }
}
