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

import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.PublicJwk;

import java.security.PublicKey;
import java.util.List;

abstract class AbstractPublicJwk<K extends PublicKey> extends AbstractAsymmetricJwk<K> implements PublicJwk<K> {
    AbstractPublicJwk(JwkContext<K> ctx, List<Parameter<?>> thumbprintParams) {
        super(ctx, thumbprintParams);
    }

    @Override
    protected final boolean equals(Jwk<?> jwk) {
        return jwk instanceof PublicJwk && equals((PublicJwk<?>) jwk);
    }

    protected abstract boolean equals(PublicJwk<?> jwk);
}
