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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.VerifySecureDigestRequest;

import java.io.InputStream;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultVerifySecureDigestRequest<K extends Key> extends DefaultSecureRequest<InputStream, K> implements VerifySecureDigestRequest<K> {

    private final byte[] digest;

    public DefaultVerifySecureDigestRequest(InputStream payload, Provider provider, SecureRandom secureRandom, K key, byte[] digest) {
        super(payload, provider, secureRandom, key);
        this.digest = Assert.notEmpty(digest, "Digest byte array cannot be null or empty.");
    }

    @Override
    public byte[] getDigest() {
        return this.digest;
    }
}
