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

import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Supplier;
import io.jsonwebtoken.security.DynamicJwkBuilder;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyOperationPolicy;

import java.security.Provider;
import java.util.Map;

public class DefaultJwkParser extends AbstractJwkParser<Jwk<?>> {

    protected final JwkConverter<Jwk<?>> CONVERTER;

    @SuppressWarnings("unchecked")
    public DefaultJwkParser(final Provider provider, Deserializer<Map<String, ?>> deserializer,
                            final KeyOperationPolicy policy) {
        super(provider, deserializer, policy);
        Supplier<DynamicJwkBuilder<?, ?>> supplier = new Supplier<DynamicJwkBuilder<?, ?>>() {
            @Override
            public DynamicJwkBuilder<?, ?> get() {
                return Jwks.builder().provider(provider).operationPolicy(policy);
            }
        };
        CONVERTER = new JwkConverter<>((Class<Jwk<?>>) (Class<?>) Jwk.class, supplier);
    }

    @Override
    protected Jwk<?> convert(Map<String, ?> m) {
        return applyFrom(m);
    }

    protected Jwk<?> applyFrom(Object o) {
        return CONVERTER.applyFrom(o);
    }
}
