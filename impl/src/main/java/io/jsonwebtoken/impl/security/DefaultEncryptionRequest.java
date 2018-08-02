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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.AeadRequest;
import io.jsonwebtoken.security.AssociatedDataSource;
import io.jsonwebtoken.security.InitializationVectorSource;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultEncryptionRequest<T, K extends Key> extends DefaultCryptoRequest<T, K> implements AeadRequest<T, K>, InitializationVectorSource {

    private final byte[] iv;

    private final byte[] aad;

    public DefaultEncryptionRequest(T data, K key, Provider provider, SecureRandom secureRandom, byte[] iv, byte[] aad) {
        super(data, key, provider, secureRandom);
        this.iv = iv;
        this.aad = aad;
    }

    @Override
    public byte[] getAssociatedData() {
        return this.aad;
    }

    @Override
    public byte[] getInitializationVector() {
        return this.iv;
    }
}
