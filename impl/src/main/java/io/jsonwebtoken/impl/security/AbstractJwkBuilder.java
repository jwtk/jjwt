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
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.security.HashAlgorithm;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkBuilder;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyOperation;
import io.jsonwebtoken.security.KeyOperationPolicy;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.SecretJwk;
import io.jsonwebtoken.security.SecretJwkBuilder;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

abstract class AbstractJwkBuilder<K extends Key, J extends Jwk<K>, T extends JwkBuilder<K, J, T>>
        extends DelegatingMapMutator<String, Object, JwkContext<K>, T>
        implements JwkBuilder<K, J, T> {

    protected final JwkFactory<K, J> jwkFactory;

    static final KeyOperationPolicy DEFAULT_OPERATION_POLICY = Jwks.OP.policy().build();

    protected KeyOperationPolicy opsPolicy = DEFAULT_OPERATION_POLICY; // default

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
    public T operation(KeyOperation operation) throws IllegalArgumentException {
        Assert.notNull(operation, "KeyOperation cannot be null.");
        return operations(Collections.setOf(operation));
    }

    @Override
    public T operations(Collection<KeyOperation> ops) {
        Assert.notEmpty(ops, "KeyOperations collection argument cannot be null or empty.");
        Set<KeyOperation> set = new LinkedHashSet<>(ops); // new ones override existing ones
        Set<KeyOperation> existing = this.DELEGATE.getOperations();
        if (!Collections.isEmpty(existing)) {
            set.addAll(existing);
        }
        this.opsPolicy.validate(set);
        this.DELEGATE.setOperations(set);
        return self();
    }

    @Override
    public T operationPolicy(KeyOperationPolicy policy) throws IllegalArgumentException {
        Assert.notNull(policy, "Policy cannot be null.");
        Collection<KeyOperation> ops = policy.getOperations();
        Assert.notEmpty(ops, "Policy operations cannot be null or empty.");
        this.opsPolicy = policy;

        // update the JWK internal param to enable the policy's values:
        Registry<String, KeyOperation> registry = new IdRegistry<>("JSON Web Key Operation", ops);
        Parameter<Set<KeyOperation>> param = Parameters.builder(KeyOperation.class)
                .setConverter(new KeyOperationConverter(registry)).set()
                .setId(AbstractJwk.KEY_OPS.getId())
                .setName(AbstractJwk.KEY_OPS.getName())
                .build();
        setDelegate(this.DELEGATE.parameter(param));
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
            this.opsPolicy.validate(this.DELEGATE.get(AbstractJwk.KEY_OPS));
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
            // assign a standard algorithm if possible:
            Key key = Assert.notNull(ctx.getKey(), "SecretKey cannot be null.");
            DefaultMacAlgorithm mac = DefaultMacAlgorithm.findByKey(key);
            if (mac != null) {
                algorithm(mac.getId());
            }
        }
    }
}
