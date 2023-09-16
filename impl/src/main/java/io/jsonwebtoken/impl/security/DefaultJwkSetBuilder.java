/*
 * Copyright © 2023 jsonwebtoken.io
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

import io.jsonwebtoken.impl.ParameterMap;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.JwkSetBuilder;
import io.jsonwebtoken.security.KeyOperationPolicy;

import java.security.Provider;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class DefaultJwkSetBuilder extends AbstractSecurityBuilder<JwkSet, JwkSetBuilder>
        implements JwkSetBuilder {

    private KeyOperationPolicy operationPolicy;
    private JwkSetConverter converter;
    private ParameterMap map;

    public DefaultJwkSetBuilder() {
        this.operationPolicy = AbstractJwkBuilder.DEFAULT_OPERATION_POLICY;
        this.converter = new JwkSetConverter();
        this.map = new ParameterMap(Parameters.registry(DefaultJwkSet.KEYS));
    }

    @Override
    public JwkSetBuilder delete(String key) {
        map.remove(key);
        return this;
    }

    @Override
    public JwkSetBuilder empty() {
        map.clear();
        return this;
    }

    @Override
    public JwkSetBuilder add(String key, Object value) {
        map.put(key, value);
        return this;
    }

    @Override
    public JwkSetBuilder add(Map<? extends String, ?> m) {
        map.putAll(m);
        return this;
    }

    private JwkSetBuilder refresh() {
        JwkConverter<Jwk<?>> jwkConverter = new JwkConverter<>(new JwkBuilderSupplier(this.provider, this.operationPolicy));
        this.converter = new JwkSetConverter(jwkConverter, this.converter.isIgnoreUnsupported());
        Parameter<Set<Jwk<?>>> param = DefaultJwkSet.param(jwkConverter);
        this.map = new ParameterMap(Parameters.registry(param), this.map, true);
        // a new policy could have been applied, ensure that any existing keys match that policy:
        Set<Jwk<?>> jwks = this.map.get(param);
        if (!Collections.isEmpty(jwks)) {
            for (Jwk<?> jwk : jwks) {
                this.operationPolicy.validate(jwk.getOperations());
            }
        }
        return this;
    }

    @Override
    public JwkSetBuilder provider(Provider provider) {
        super.provider(provider);
        return refresh();
    }

    @Override
    public JwkSetBuilder operationPolicy(final KeyOperationPolicy policy) throws IllegalArgumentException {
        this.operationPolicy = policy != null ? policy : AbstractJwkBuilder.DEFAULT_OPERATION_POLICY;
        return refresh();
    }

    Collection<Jwk<?>> ensureKeys() {
        Collection<Jwk<?>> keys = map.get(DefaultJwkSet.KEYS);
        return Collections.isEmpty(keys) ? new LinkedHashSet<Jwk<?>>() : keys;
    }

    @Override
    public JwkSetBuilder add(Jwk<?> jwk) {
        if (jwk != null) {
            this.operationPolicy.validate(jwk.getOperations());
            Collection<Jwk<?>> keys = ensureKeys();
            keys.add(jwk);
            keys(keys);
        }
        return this;
    }

    @Override
    public JwkSetBuilder add(Collection<Jwk<?>> c) {
        if (!Collections.isEmpty(c)) {
            for (Jwk<?> jwk : c) {
                add(jwk);
            }
        }
        return this;
    }

    @Override
    public JwkSetBuilder keys(Collection<Jwk<?>> c) {
        return add(DefaultJwkSet.KEYS.getId(), c);
    }

    @Override
    public JwkSet build() {
        return converter.applyFrom(this.map);
    }
}
