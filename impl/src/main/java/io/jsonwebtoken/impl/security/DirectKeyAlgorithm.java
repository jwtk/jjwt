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
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DirectKeyAlgorithm implements KeyAlgorithm<SecretKey, SecretKey> {

    static final String ID = "dir";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public KeyResult getEncryptionKey(final KeyRequest<SecretKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        SecretKey key = Assert.notNull(request.getPayload(), "Encryption key cannot be null.");
        return new DefaultKeyResult(key);
    }

    @Override
    public SecretKey getDecryptionKey(DecryptionKeyRequest<SecretKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        return Assert.notNull(request.getKey(), "Decryption key cannot be null.");
    }
}
