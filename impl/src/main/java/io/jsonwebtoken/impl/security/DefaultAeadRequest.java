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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadRequest;
import io.jsonwebtoken.security.InitializationVectorSupplier;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultAeadRequest extends DefaultSecureRequest<InputStream, SecretKey>
        implements AeadRequest, InitializationVectorSupplier {

    private final byte[] IV;

    private final InputStream AAD;

    private final OutputStream out;

    DefaultAeadRequest(InputStream payload, OutputStream out, Provider provider, SecureRandom secureRandom,
                       SecretKey key, InputStream aad, byte[] iv) {
        super(payload, provider, secureRandom, key);
        this.AAD = aad;
        this.IV = iv;
        this.out = Assert.notNull(out, "OutputStream cannot be null.");
    }

    public DefaultAeadRequest(InputStream payload, OutputStream out, Provider provider, SecureRandom secureRandom,
                              SecretKey key, InputStream aad) {
        this(payload, out, provider, secureRandom, key, aad, null);
    }

    @Override
    public InputStream getAssociatedData() {
        return this.AAD;
    }

    @Override
    public byte[] getInitializationVector() {
        return this.IV;
    }

    @Override
    public OutputStream getOutputStream() {
        return this.out;
    }
}
