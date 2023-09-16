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

import io.jsonwebtoken.impl.AbstractX509Context;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.security.HashAlgorithm;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyOperation;

import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static io.jsonwebtoken.lang.Strings.nespace;

public class DefaultJwkContext<K extends Key> extends AbstractX509Context<JwkContext<K>> implements JwkContext<K> {

    private static final Set<Parameter<?>> DEFAULT_PARAMS;

    static { // assume all JWA params:
        Set<Parameter<?>> set = new LinkedHashSet<>();
        set.addAll(DefaultSecretJwk.PARAMS); // Private/Secret JWKs has both public and private params
        set.addAll(DefaultEcPrivateJwk.PARAMS); // Private JWKs have both public and private params
        set.addAll(DefaultRsaPrivateJwk.PARAMS); // Private JWKs have both public and private params
        set.addAll(DefaultOctetPrivateJwk.PARAMS); // Private JWKs have both public and private params

        // EC JWKs and Octet JWKs have two params that are named identically, but have different type requirements.  So
        // we swap out those params with placeholders that allow either.  When the JwkContext is converted to its
        // type-specific context by the ProtoBuilder, the values will be correctly converted to their required types
        // at that time.  It is also important to retain toString security (via parameter.setSecret(true)) to ensure
        // any printing of the builder or its internal context does not print secure data.
        set.remove(DefaultEcPublicJwk.X);
        set.remove(DefaultEcPrivateJwk.D);
        set.add(Parameters.string(DefaultEcPublicJwk.X.getId(), "Elliptic Curve public key X coordinate"));
        set.add(Parameters.builder(String.class).setSecret(true)
                .setId(DefaultEcPrivateJwk.D.getId()).setName("Elliptic Curve private key").build());

        DEFAULT_PARAMS = Collections.immutable(set);
    }

    private K key;
    private PublicKey publicKey;
    private Provider provider;

    private SecureRandom random;

    private HashAlgorithm idThumbprintAlgorithm;

    public DefaultJwkContext() {
        // For the default constructor case, we don't know how it will be used or what values will be populated,
        // so we can't know ahead of time what the sensitive data is.  As such, for security reasons, we assume all
        // the known params for all supported keys/algorithms in case it is used for any of them:
        this(DEFAULT_PARAMS);
    }

    public DefaultJwkContext(Set<Parameter<?>> params) {
        super(params);
    }

    public DefaultJwkContext(Set<Parameter<?>> params, JwkContext<?> other) {
        this(params, other, true);
    }

    public DefaultJwkContext(Set<Parameter<?>> params, JwkContext<?> other, K key) {
        //if the key is null or a PublicKey, we don't want to redact - we want to fully remove the items that are
        //private names (public JWKs should never contain any private key params, even if redacted):
        this(params, other, (key == null || key instanceof PublicKey));
        this.key = Assert.notNull(key, "Key cannot be null.");
    }

    public DefaultJwkContext(Set<Parameter<?>> params, JwkContext<?> other, boolean removePrivate) {
        super(Assert.notEmpty(params, "Parameters cannot be null or empty."));
        Assert.notNull(other, "JwkContext cannot be null.");
        Assert.isInstanceOf(DefaultJwkContext.class, other, "JwkContext must be a DefaultJwkContext instance.");
        DefaultJwkContext<?> src = (DefaultJwkContext<?>) other;
        this.provider = other.getProvider();
        this.random = other.getRandom();
        this.idThumbprintAlgorithm = other.getIdThumbprintAlgorithm();
        this.values.putAll(src.values);
        // Ensure the source's idiomatic values match the types expected by this object:
        for (Map.Entry<String, Object> entry : src.idiomaticValues.entrySet()) {
            String id = entry.getKey();
            Object value = entry.getValue();
            Parameter<?> param = this.PARAMS.get(id);
            if (param != null && !param.supports(value)) { // src idiomatic value is not what is expected, so convert:
                value = this.values.get(param.getId());
                put(param, value); // perform idiomatic conversion with original/raw src value
            } else {
                this.idiomaticValues.put(id, value);
            }
        }
        if (removePrivate) {
            for (Parameter<?> param : src.PARAMS.values()) {
                if (param.isSecret()) {
                    remove(param.getId());
                }
            }
        }
    }

    @Override
    public JwkContext<K> parameter(Parameter<?> param) {
        Registry<String, ? extends Parameter<?>> registry = Parameters.replace(this.PARAMS, param);
        Set<Parameter<?>> params = new LinkedHashSet<>(registry.values());
        return this.key != null ?
                new DefaultJwkContext<>(params, this, key) :
                new DefaultJwkContext<K>(params, this, false);
    }

    @Override
    public String getName() {
        String value = get(AbstractJwk.KTY);
        if (DefaultSecretJwk.TYPE_VALUE.equals(value)) {
            value = "Secret";
        } else if (DefaultOctetPublicJwk.TYPE_VALUE.equals(value)) {
            value = "Octet";
        }
        StringBuilder sb = value != null ? new StringBuilder(value) : new StringBuilder();
        K key = getKey();
        if (key instanceof PublicKey) {
            nespace(sb).append("Public");
        } else if (key instanceof PrivateKey) {
            nespace(sb).append("Private");
        }
        nespace(sb).append("JWK");
        return sb.toString();
    }

    @Override
    public void putAll(Map<? extends String, ?> m) {
        Assert.notEmpty(m, "JWK values cannot be null or empty.");
        super.putAll(m);
    }

    @Override
    public String getAlgorithm() {
        return get(AbstractJwk.ALG);
    }

    @Override
    public JwkContext<K> setAlgorithm(String algorithm) {
        put(AbstractJwk.ALG, algorithm);
        return this;
    }

    @Override
    public String getId() {
        return get(AbstractJwk.KID);
    }

    @Override
    public JwkContext<K> setId(String id) {
        put(AbstractJwk.KID, id);
        return this;
    }

    @Override
    public JwkContext<K> setIdThumbprintAlgorithm(HashAlgorithm alg) {
        this.idThumbprintAlgorithm = alg;
        return this;
    }

    @Override
    public HashAlgorithm getIdThumbprintAlgorithm() {
        return this.idThumbprintAlgorithm;
    }

    @Override
    public Set<KeyOperation> getOperations() {
        return get(AbstractJwk.KEY_OPS);
    }

    @Override
    public JwkContext<K> setOperations(Collection<KeyOperation> ops) {
        put(AbstractJwk.KEY_OPS, ops);
        return this;
    }

    @Override
    public String getType() {
        return get(AbstractJwk.KTY);
    }

    @Override
    public JwkContext<K> setType(String type) {
        put(AbstractJwk.KTY, type);
        return this;
    }

    @Override
    public String getPublicKeyUse() {
        return get(AbstractAsymmetricJwk.USE);
    }

    @Override
    public JwkContext<K> setPublicKeyUse(String use) {
        put(AbstractAsymmetricJwk.USE, use);
        return this;
    }

    @Override
    public boolean isSigUse() {
        // Even though 'use' is for PUBLIC KEY use (as defined in RFC 7515), RFC 7520 shows secret keys with
        // 'use' values, so we'll account for that as well:
        if ("sig".equals(getPublicKeyUse())) {
            return true;
        }
        Set<KeyOperation> ops = getOperations();
        if (Collections.isEmpty(ops)) {
            return false;
        }
        return ops.contains(Jwks.OP.SIGN) || ops.contains(Jwks.OP.VERIFY);
    }

    @Override
    public K getKey() {
        return this.key;
    }

    @Override
    public JwkContext<K> setKey(K key) {
        this.key = key;
        return this;
    }

    @Override
    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    @Override
    public JwkContext<K> setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    @Override
    public Provider getProvider() {
        return this.provider;
    }

    @Override
    public JwkContext<K> setProvider(Provider provider) {
        this.provider = provider;
        return this;
    }

    @Override
    public SecureRandom getRandom() {
        return this.random;
    }

    @Override
    public JwkContext<K> setRandom(SecureRandom random) {
        this.random = random;
        return this;
    }
}
