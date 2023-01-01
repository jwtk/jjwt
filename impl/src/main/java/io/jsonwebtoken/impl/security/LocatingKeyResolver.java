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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.lang.Assert;

import java.security.Key;

@SuppressWarnings("deprecation") // TODO: delete this class for 1.0
public class LocatingKeyResolver implements SigningKeyResolver {

    private final Locator<? extends Key> locator;

    public LocatingKeyResolver(Locator<? extends Key> locator) {
        this.locator = Assert.notNull(locator, "Locator cannot be null.");
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        return this.locator.locate(header);
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, byte[] content) {
        return this.locator.locate(header);
    }
}
