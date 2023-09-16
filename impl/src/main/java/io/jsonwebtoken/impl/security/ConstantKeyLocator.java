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

import io.jsonwebtoken.Header;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.impl.lang.Function;

import java.security.Key;

public class ConstantKeyLocator extends LocatorAdapter<Key> implements Function<Header, Key> {

    private final Key jwsKey;
    private final Key jweKey;

    public ConstantKeyLocator(Key jwsKey, Key jweKey) {
        this.jwsKey = jwsKey;
        this.jweKey = jweKey;
    }

    @Override
    protected Key locate(JwsHeader header) {
        return this.jwsKey;
    }

    @Override
    protected Key locate(JweHeader header) {
        return this.jweKey;
    }

    @Override
    public Key apply(Header header) {
        return locate(header);
    }
}
