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
import io.jsonwebtoken.security.Jwk;

import java.security.Key;

class AsymmetricJwkFactory implements FamilyJwkFactory<Key, Jwk<Key>> {

    private final String id;
    private final FamilyJwkFactory<Key, Jwk<Key>> publicFactory;
    private final FamilyJwkFactory<Key, Jwk<Key>> privateFactory;

    @SuppressWarnings({"unchecked", "rawtypes"})
    AsymmetricJwkFactory(FamilyJwkFactory publicFactory, FamilyJwkFactory privateFactory) {
        this.publicFactory = (FamilyJwkFactory<Key, Jwk<Key>>) Assert.notNull(publicFactory, "publicFactory cannot be null.");
        this.privateFactory = (FamilyJwkFactory<Key, Jwk<Key>>) Assert.notNull(privateFactory, "privateFactory cannot be null.");
        this.id = Assert.notNull(publicFactory.getId(), "publicFactory id cannot be null or empty.");
        Assert.isTrue(this.id.equals(privateFactory.getId()), "privateFactory id must equal publicFactory id");
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public boolean supports(JwkContext<?> ctx) {
        return ctx != null &&
                (this.id.equals(ctx.getType()) || privateFactory.supports(ctx) || publicFactory.supports(ctx));
    }

    @Override
    public boolean supports(Key key) {
        return key != null && (privateFactory.supports(key) || publicFactory.supports(key));
    }

    @Override
    public JwkContext<Key> newContext(JwkContext<?> src, Key key) {
        return (privateFactory.supports(key) || privateFactory.supports(src)) ?
                privateFactory.newContext(src, key) :
                publicFactory.newContext(src, key);
    }

    @Override
    public Jwk<Key> createJwk(JwkContext<Key> ctx) {
        if (privateFactory.supports(ctx)) {
            return this.privateFactory.createJwk(ctx);
        }
        return this.publicFactory.createJwk(ctx);
    }
}
