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
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.security.Key;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

class DispatchingJwkFactory implements JwkFactory<Key, Jwk<Key>> {

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Collection<FamilyJwkFactory<Key, ?>> createDefaultFactories() {
        List families = new ArrayList<>(3);
        families.add(new SecretJwkFactory());
        families.add(new AsymmetricJwkFactory(EcPublicJwkFactory.INSTANCE, new EcPrivateJwkFactory()));
        families.add(new AsymmetricJwkFactory(RsaPublicJwkFactory.INSTANCE, new RsaPrivateJwkFactory()));
        families.add(new AsymmetricJwkFactory(OctetPublicJwkFactory.INSTANCE, new OctetPrivateJwkFactory()));
        return families;
    }

    private static final Collection<FamilyJwkFactory<Key, ?>> DEFAULT_FACTORIES = createDefaultFactories();
    static final JwkFactory<Key, Jwk<Key>> DEFAULT_INSTANCE = new DispatchingJwkFactory();

    private final Collection<FamilyJwkFactory<Key, ?>> factories;

    DispatchingJwkFactory() {
        this(DEFAULT_FACTORIES);
    }

    @SuppressWarnings("unchecked")
    DispatchingJwkFactory(Collection<? extends FamilyJwkFactory<?, ?>> factories) {
        Assert.notEmpty(factories, "FamilyJwkFactory collection cannot be null or empty.");
        this.factories = new ArrayList<>(factories.size());
        for (FamilyJwkFactory<?, ?> factory : factories) {
            Assert.hasText(factory.getId(), "FamilyJwkFactory.getFactoryId() cannot return null or empty.");
            this.factories.add((FamilyJwkFactory<Key, ?>) factory);
        }
    }

    @Override
    public JwkContext<Key> newContext(JwkContext<?> src, Key key) {
        Assert.notNull(src, "JwkContext cannot be null.");
        String kty = src.getType();
        assertKeyOrKeyType(key, kty);
        for (FamilyJwkFactory<Key, ?> factory : this.factories) {
            if (factory.supports(key) || factory.supports(src)) {
                JwkContext<Key> ctx = factory.newContext(src, key);
                return Assert.notNull(ctx, "FamilyJwkFactory implementation cannot return null JwkContexts.");
            }
        }
        throw noFamily(key, kty);
    }

    private static void assertKeyOrKeyType(Key key, String kty) {
        if (key == null && !Strings.hasText(kty)) {
            String msg = "Either a Key instance or a " + AbstractJwk.KTY + " value is required to create a JWK.";
            throw new InvalidKeyException(msg);
        }
    }

    @Override
    public Jwk<Key> createJwk(JwkContext<Key> ctx) {

        Assert.notNull(ctx, "JwkContext cannot be null.");

        final Key key = ctx.getKey();
        final String kty = Strings.clean(ctx.getType());
        assertKeyOrKeyType(key, kty);

        for (FamilyJwkFactory<Key, ?> factory : this.factories) {
            if (factory.supports(ctx)) {
                String algFamilyId = Assert.hasText(factory.getId(), "factory id cannot be null or empty.");
                if (kty == null) {
                    ctx.setType(algFamilyId); //ensure the kty is available for the rest of the creation process
                }
                return factory.createJwk(ctx);
            }
        }

        // if nothing has been returned at this point, no factory supported the JwkContext, so that's an error:
        throw noFamily(key, kty);
    }

    private static UnsupportedKeyException noFamily(Key key, String kty) {
        String reason = key != null ?
                "key of type " + key.getClass().getName() :
                "kty value '" + kty + "'";
        String msg = "Unable to create JWK for unrecognized " + reason +
                ": there is no known JWK Factory capable of creating JWKs for this key type.";
        return new UnsupportedKeyException(msg);
    }
}
