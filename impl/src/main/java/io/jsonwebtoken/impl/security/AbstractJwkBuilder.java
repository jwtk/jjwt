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
import io.jsonwebtoken.security.HashAlgorithm;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkBuilder;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.SecretJwk;
import io.jsonwebtoken.security.SecretJwkBuilder;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;

abstract class AbstractJwkBuilder<K extends Key, J extends Jwk<K>, T extends JwkBuilder<K, J, T>> implements JwkBuilder<K, J, T> {

    protected JwkContext<K> jwkContext;
    protected final JwkFactory<K, J> jwkFactory;

    @SuppressWarnings("unchecked")
    protected AbstractJwkBuilder(JwkContext<K> jwkContext) {
        this(jwkContext, (JwkFactory<K, J>) DispatchingJwkFactory.DEFAULT_INSTANCE);
    }

    // visible for testing
    protected AbstractJwkBuilder(JwkContext<K> context, JwkFactory<K, J> factory) {
        this.jwkFactory = Assert.notNull(factory, "JwkFactory cannot be null.");
        setContext(context);
    }

    @SuppressWarnings("unchecked")
    protected <A extends Key> JwkContext<A> newContext(A key) {
        return (JwkContext<A>) this.jwkFactory.newContext(this.jwkContext, (K) key);
    }

    protected void setContext(JwkContext<K> ctx) {
        this.jwkContext = Assert.notNull(ctx, "JwkContext cannot be null.");
    }

    @Override
    public T setProvider(Provider provider) {
        jwkContext.setProvider(provider);
        return self();
    }

    @Override
    public T setRandom(SecureRandom random) {
        jwkContext.setRandom(random);
        return self();
    }

    @Override
    public T put(String name, Object value) {
        jwkContext.put(name, value);
        return self();
    }

    @Override
    public T putAll(Map<? extends String, ?> values) {
        jwkContext.putAll(values);
        return self();
    }

    @Override
    public T remove(String key) {
        jwkContext.remove(key);
        return self();
    }

    @Override
    public T clear() {
        jwkContext.clear();
        return self();
    }

    @Override
    public T setAlgorithm(String alg) {
        Assert.hasText(alg, "Algorithm cannot be null or empty.");
        jwkContext.setAlgorithm(alg);
        return self();
    }

    @Override
    public T setId(String id) {
        Assert.hasText(id, "Id cannot be null or empty.");
        jwkContext.setIdThumbprintAlgorithm(null); //clear out any previously set value
        jwkContext.setId(id);
        return self();
    }

    @Override
    public T setIdFromThumbprint() {
        return setIdFromThumbprint(Jwks.HASH.SHA256);
    }

    @Override
    public T setIdFromThumbprint(HashAlgorithm alg) {
        Assert.notNull(alg, "Thumbprint HashAlgorithm cannot be null.");
        Assert.notNull(alg.getId(), "Thumbprint HashAlgorithm ID cannot be null.");
        this.jwkContext.setId(null); // clear out any previous value
        this.jwkContext.setIdThumbprintAlgorithm(alg);
        return self();
    }

    @Override
    public T setOperations(Set<String> ops) {
        Assert.notEmpty(ops, "Operations cannot be null or empty.");
        jwkContext.setOperations(ops);
        return self();
    }

    @SuppressWarnings("unchecked")
    protected final T self() {
        return (T) this;
    }

    @Override
    public J build() {

        //should always exist as there isn't a way to set it outside the constructor:
        Assert.stateNotNull(this.jwkContext, "JwkContext should always be non-null");

        K key = this.jwkContext.getKey();
        if (key == null && this.jwkContext.isEmpty()) {
            String msg = "A " + Key.class.getName() + " or one or more name/value pairs must be provided to create a JWK.";
            throw new IllegalStateException(msg);
        }
        try {
            return jwkFactory.createJwk(this.jwkContext);
        } catch (IllegalArgumentException iae) {
            //if we get an IAE, it means the builder state wasn't configured enough in order to create
            String msg = "Unable to create JWK: " + iae.getMessage();
            throw new MalformedKeyException(msg, iae);
        }
    }

    static class DefaultSecretJwkBuilder extends AbstractJwkBuilder<SecretKey, SecretJwk, SecretJwkBuilder>
            implements SecretJwkBuilder {
        public DefaultSecretJwkBuilder(JwkContext<SecretKey> ctx) {
            super(ctx);
        }
    }
}
