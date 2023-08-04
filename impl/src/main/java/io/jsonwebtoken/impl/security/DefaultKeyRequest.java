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

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.KeyRequest;

import java.security.Provider;
import java.security.SecureRandom;

public class DefaultKeyRequest<T> extends DefaultRequest<T> implements KeyRequest<T> {

    private final JweHeader header;
    private final AeadAlgorithm encryptionAlgorithm;

    public DefaultKeyRequest(T payload, Provider provider, SecureRandom secureRandom, JweHeader header, AeadAlgorithm encryptionAlgorithm) {
        super(payload, provider, secureRandom);
        this.header = Assert.notNull(header, "JweHeader/Builder cannot be null.");
        this.encryptionAlgorithm = Assert.notNull(encryptionAlgorithm, "AeadAlgorithm argument cannot be null.");
    }

    @Override
    public JweHeader getHeader() {
        return this.header;
    }

    @Override
    public AeadAlgorithm getEncryptionAlgorithm() {
        return this.encryptionAlgorithm;
    }
}
