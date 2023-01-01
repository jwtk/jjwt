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

import io.jsonwebtoken.security.AeadRequest;
import io.jsonwebtoken.security.InitializationVectorSupplier;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultAeadRequest extends DefaultSecureRequest<byte[], SecretKey>
        implements AeadRequest, InitializationVectorSupplier {

    private final byte[] IV;

    private final byte[] AAD;

    DefaultAeadRequest(byte[] data, Provider provider, SecureRandom secureRandom, SecretKey key, byte[] aad, byte[] iv) {
        super(data, provider, secureRandom, key);
        this.AAD = aad;
        this.IV = iv;
    }

    public DefaultAeadRequest(byte[] data, Provider provider, SecureRandom secureRandom, SecretKey key, byte[] aad) {
        this(data, provider, secureRandom, key, aad, null);
    }

    public DefaultAeadRequest(byte[] data, SecretKey key, byte[] aad) {
        this(data, null, null, key, aad, null);
    }

    @Override
    public byte[] getAssociatedData() {
        return this.AAD;
    }

    @Override
    public byte[] getInitializationVector() {
        return this.IV;
    }
}
