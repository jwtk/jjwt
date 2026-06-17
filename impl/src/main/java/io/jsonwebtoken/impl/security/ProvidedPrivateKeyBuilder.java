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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.PrivateKeyBuilder;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.util.function.Function;

@SuppressWarnings("unused") // used via reflection as io.jsonwebtoken.security.Suppliers.PRIVATE_KEY_BUILDER_FACTORY
class ProvidedPrivateKeyBuilder extends ProvidedKeyBuilder<PrivateKey, PrivateKeyBuilder>
        implements PrivateKeyBuilder {

    private PublicKey publicKey;

    ProvidedPrivateKeyBuilder(PrivateKey key) {
        super(key);
    }

    @Override
    public PrivateKeyBuilder publicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    @Override
    public PrivateKey doBuild() {

        PrivateKey key = this.key;

        // We only need to wrap as an ECKey if:
        // 1. The private key is not already an ECKey. If it is, we can validate normally
        // 2. The private key indicates via its algorithm that it is intended to be used as an EC key.
        // 3. The public key is an ECKey - this must be true to represent EC params for the private key
        String privAlg = Strings.clean(this.key.getAlgorithm());
        if (!(key instanceof ECKey) && ("EC".equalsIgnoreCase(privAlg) || "ECDSA".equalsIgnoreCase(privAlg)) &&
                this.publicKey instanceof ECKey) {
            key = new PrivateECKey(key, ((ECKey) this.publicKey).getParams());
        }

        return this.provider != null ? new ProviderPrivateKey(this.provider, key) : key;
    }

    @SuppressWarnings("unused") // used via reflection as io.jsonwebtoken.security.Suppliers.PRIVATE_KEY_BUILDER_FACTORY
    public static class Factory implements Function<PrivateKey, PrivateKeyBuilder> {
        @Override
        public PrivateKeyBuilder apply(PrivateKey key) {
            Assert.notNull(key, "PrivateKey cannot be null.");
            return new ProvidedPrivateKeyBuilder(key);
        }
    }
}
