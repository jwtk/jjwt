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
import io.jsonwebtoken.security.SecureRequest;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

public class DefaultSecureRequest<T, K extends Key> extends DefaultRequest<T> implements SecureRequest<T, K> {

    private final K KEY;

    public DefaultSecureRequest(T payload, Provider provider, SecureRandom secureRandom, K key) {
        super(payload, provider, secureRandom);
        this.KEY = Assert.notNull(key, "key cannot be null.");
    }

    @Override
    public K getKey() {
        return this.KEY;
    }
}
