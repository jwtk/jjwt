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
import io.jsonwebtoken.security.IvSupplier;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * @since 0.12.0
 */
public class DefaultAeadRequest extends DefaultSecureRequest<InputStream, SecretKey>
        implements AeadRequest, IvSupplier {

    private final byte[] IV;

    private final InputStream AAD;

    DefaultAeadRequest(InputStream payload, Provider provider, SecureRandom secureRandom,
                       SecretKey key, InputStream aad, byte[] iv) {
        super(payload, provider, secureRandom, key);
        this.AAD = aad;
        this.IV = iv;
    }

    public DefaultAeadRequest(InputStream payload, Provider provider, SecureRandom secureRandom,
                              SecretKey key, InputStream aad) {
        this(payload, provider, secureRandom, key, aad, null);
    }

    @Override
    public InputStream getAssociatedData() {
        return this.AAD;
    }

    @Override
    public byte[] getIv() {
        return this.IV;
    }
}
