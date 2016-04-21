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

import java.security.SecureRandom;

public abstract class AbstractCryptoRequest implements CryptoRequest {

    private final SecureRandom random;
    private final byte[] key;
    private final byte[] iv;

    public AbstractCryptoRequest(SecureRandom random, byte[] key, byte[] iv) {
        this.random = random;
        this.key = key;
        this.iv = iv;
    }

    @Override
    public SecureRandom getSecureRandom() {
        return this.random;
    }

    @Override
    public byte[] getKey() {
        return this.key;
    }

    @Override
    public byte[] getInitializationVector() {
        return this.iv;
    }
}
