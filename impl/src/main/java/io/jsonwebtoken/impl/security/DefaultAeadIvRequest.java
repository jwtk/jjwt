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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadIvRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultAeadIvRequest<T, K extends Key> extends DefaultIvDecryptionRequest<T, K>
        implements AeadIvRequest<T, K> {

    private final byte[] aad;

    private final byte[] tag;

    public DefaultAeadIvRequest(T data, K key, Provider provider, SecureRandom secureRandom, byte[] iv, byte[] aad, byte[] tag) {
        super(data, key, provider, secureRandom, iv);
        this.aad = aad;
        this.tag = Assert.notEmpty(tag, "Authentication tag cannot be null or empty.");
    }

    @Override
    public byte[] getAssociatedData() {
        return this.aad;
    }

    @Override
    public byte[] getAuthenticationTag() {
        return this.tag;
    }
}
