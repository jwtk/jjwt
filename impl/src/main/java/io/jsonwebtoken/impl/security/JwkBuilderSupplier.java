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

import io.jsonwebtoken.lang.Supplier;
import io.jsonwebtoken.security.DynamicJwkBuilder;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyOperationPolicy;

import java.security.Provider;

public class JwkBuilderSupplier implements Supplier<DynamicJwkBuilder<?, ?>> {

    public static final JwkBuilderSupplier DEFAULT = new JwkBuilderSupplier(null, null);

    private final Provider provider;
    private final KeyOperationPolicy operationPolicy;

    public JwkBuilderSupplier(Provider provider, KeyOperationPolicy operationPolicy) {
        this.provider = provider;
        this.operationPolicy = operationPolicy;
    }

    @Override
    public DynamicJwkBuilder<?, ?> get() {
        DynamicJwkBuilder<?, ?> builder = Jwks.builder().provider(this.provider);
        if (this.operationPolicy != null) {
            builder.operationPolicy(operationPolicy);
        }
        return builder;
    }
}
