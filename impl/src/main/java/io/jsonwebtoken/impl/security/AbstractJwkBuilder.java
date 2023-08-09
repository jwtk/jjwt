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

import io.jsonwebtoken.impl.lang.DelegatingMapMutator;
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
import java.util.Set;

abstract class AbstractJwkBuilder<K extends Key, J extends Jwk<K>, T extends JwkBuilder<K, J, T>>
        extends DelegatingMapMutator<String, Object, JwkContext<K>, T>
        implements JwkBuilder<K, J, T> {

    protected final JwkFactory<K, J> jwkFactory;

    @SuppressWarnings("unchecked")
    protected AbstractJwkBuilder(JwkContext<K> jwkContext) {
        this(jwkContext, (JwkFactory<K, J>) DispatchingJwkFactory.DEFAULT_INSTANCE);
    }

    // visible for testing
    protected AbstractJwkBuilder(JwkContext<K> context, JwkFactory<K, J> factory) {
        super(context);
        this.jwkFactory = Assert.notNull(factory, "JwkFactory cannot be null.");
    }

    @SuppressWarnings("unchecked")
    protected <A extends Key> JwkContext<A> newContext(A key) {
        return (JwkContext<A>) this.jwkFactory.newContext(this.DELEGATE, (K) key);
    }

    @Override
    public T provider(Provider provider) {
        this.DELEGATE.setProvider(provider);
        return self();
    }

    @Override
    public T random(SecureRandom random) {
        this.DELEGATE.setRandom(random);
        return self();
    }

    @Override
    public T algorithm(String alg) {
        Assert.hasText(alg, "Algorithm cannot be null or empty.");
        this.DELEGATE.setAlgorithm(alg);
        return self();
    }

    @Override
    public T id(String id) {
        Assert.hasText(id, "Id cannot be null or empty.");
        this.DELEGATE.setIdThumbprintAlgorithm(null); //clear out any previously set value
        this.DELEGATE.setId(id);
        return self();
    }

    @Override
    public T idFromThumbprint() {
        return idFromThumbprint(Jwks.HASH.SHA256);
    }

    @Override
    public T idFromThumbprint(HashAlgorithm alg) {
        Assert.notNull(alg, "Thumbprint HashAlgorithm cannot be null.");
        Assert.notNull(alg.getId(), "Thumbprint HashAlgorithm ID cannot be null.");
        this.DELEGATE.setId(null); // clear out any previous value
        this.DELEGATE.setIdThumbprintAlgorithm(alg);
        return self();
    }

    @Override
    public T operations(Set<String> ops) {
        Assert.notEmpty(ops, "Operations cannot be null or empty.");
        this.DELEGATE.setOperations(ops);
        return self();
    }

    @Override
    public J build() {

        //should always exist as there isn't a way to set it outside the constructor:
        Assert.stateNotNull(this.DELEGATE, "JwkContext should always be non-null");

        K key = this.DELEGATE.getKey();
        if (key == null && isEmpty()) {
            String msg = "A " + Key.class.getName() + " or one or more name/value pairs must be provided to create a JWK.";
            throw new IllegalStateException(msg);
        }
        try {
            return jwkFactory.createJwk(this.DELEGATE);
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
