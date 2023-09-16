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

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.KeyException;

import java.security.Key;
import java.security.KeyFactory;
import java.util.Set;

abstract class AbstractFamilyJwkFactory<K extends Key, J extends Jwk<K>> implements FamilyJwkFactory<K, J> {

    protected static <T> void put(JwkContext<?> ctx, Parameter<T> param, T value) {
        ctx.put(param.getId(), param.applyTo(value));
    }

    private final String ktyValue;
    private final Class<K> keyType;
    private final Set<Parameter<?>> params;

    AbstractFamilyJwkFactory(String ktyValue, Class<K> keyType, Set<Parameter<?>> params) {
        this.ktyValue = Assert.hasText(ktyValue, "keyType argument cannot be null or empty.");
        this.keyType = Assert.notNull(keyType, "keyType class cannot be null.");
        this.params = Assert.notEmpty(params, "Parameters collection cannot be null or empty.");
    }

    @Override
    public String getId() {
        return this.ktyValue;
    }

    @Override
    public boolean supports(Key key) {
        return this.keyType.isInstance(key);
    }

    @Override
    public JwkContext<K> newContext(JwkContext<?> src, K key) {
        Assert.notNull(src, "Source JwkContext cannot be null.");
        return key != null ?
                new DefaultJwkContext<>(this.params, src, key) :
                new DefaultJwkContext<K>(this.params, src, false);
    }

    @Override
    public boolean supports(JwkContext<?> ctx) {
        return supports(ctx.getKey()) || supportsKeyValues(ctx);
    }

    protected boolean supportsKeyValues(JwkContext<?> ctx) {
        return this.ktyValue.equals(ctx.getType());
    }

    protected K generateKey(final JwkContext<K> ctx, final CheckedFunction<KeyFactory, K> fn) {
        return generateKey(ctx, this.keyType, fn);
    }

    protected String getKeyFactoryJcaName(final JwkContext<?> ctx) {
        String jcaName = KeysBridge.findAlgorithm(ctx.getKey());
        return Strings.hasText(jcaName) ? jcaName : getId();
    }

    protected <T extends Key> T generateKey(final JwkContext<?> ctx, final Class<T> type, final CheckedFunction<KeyFactory, T> fn) {
        String jcaName = getKeyFactoryJcaName(ctx);
        JcaTemplate template = new JcaTemplate(jcaName, ctx.getProvider(), ctx.getRandom());
        return template.withKeyFactory(new CheckedFunction<KeyFactory, T>() {
            @Override
            public T apply(KeyFactory instance) {
                try {
                    return fn.apply(instance);
                } catch (KeyException keyException) {
                    throw keyException; // propagate
                } catch (Exception e) {
                    String msg = "Unable to create " + type.getSimpleName() + " from JWK " + ctx + ": " + e.getMessage();
                    throw new InvalidKeyException(msg, e);
                }
            }
        });
    }

    @Override
    public final J createJwk(JwkContext<K> ctx) {
        Assert.notNull(ctx, "JwkContext argument cannot be null.");
        if (!supports(ctx)) { //should be asserted by caller, but assert just in case:
            String msg = "Unsupported JwkContext.";
            throw new IllegalArgumentException(msg);
        }
        K key = ctx.getKey();
        if (key != null) {
            ctx.setType(this.ktyValue);
            return createJwkFromKey(ctx);
        } else {
            return createJwkFromValues(ctx);
        }
    }

    //when called, ctx.getKey() is guaranteed to be non-null
    protected abstract J createJwkFromKey(JwkContext<K> ctx);

    //when called ctx.getType() is guaranteed to equal this.ktyValue
    protected abstract J createJwkFromValues(JwkContext<K> ctx);
}
