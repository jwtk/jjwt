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
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.KeyPair;
import io.jsonwebtoken.security.PrivateJwk;
import io.jsonwebtoken.security.PublicJwk;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

abstract class AbstractPrivateJwk<K extends PrivateKey, L extends PublicKey, M extends PublicJwk<L>> extends AbstractAsymmetricJwk<K> implements PrivateJwk<K, L, M> {

    private final M publicJwk;
    private final KeyPair<L, K> keyPair;

    AbstractPrivateJwk(JwkContext<K> ctx, List<Parameter<?>> thumbprintParams, M pubJwk) {
        super(ctx, thumbprintParams);
        this.publicJwk = Assert.notNull(pubJwk, "PublicJwk instance cannot be null.");
        L publicKey = Assert.notNull(pubJwk.toKey(), "PublicJwk key instance cannot be null.");
        this.context.setPublicKey(publicKey);
        this.keyPair = new DefaultKeyPair<>(publicKey, toKey());
    }

    @Override
    public M toPublicJwk() {
        return this.publicJwk;
    }

    @Override
    public KeyPair<L, K> toKeyPair() {
        return this.keyPair;
    }

    @Override
    protected final boolean equals(Jwk<?> jwk) {
        return jwk instanceof PrivateJwk && equals((PrivateJwk<?, ?, ?>) jwk);
    }

    protected abstract boolean equals(PrivateJwk<?, ?, ?> jwk);
}
