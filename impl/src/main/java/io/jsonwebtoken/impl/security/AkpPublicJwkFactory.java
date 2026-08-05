/*
 * Copyright © 2026 jsonwebtoken.io
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

import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.impl.lang.RequiredParameterReader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AkpPublicJwk;

import java.security.PublicKey;

public class AkpPublicJwkFactory extends AkpJwkFactory<PublicKey, AkpPublicJwk<PublicKey>> {

    static final AkpPublicJwkFactory INSTANCE = new AkpPublicJwkFactory();

    AkpPublicJwkFactory() {
        super(PublicKey.class, DefaultAkpPublicJwk.PARAMS);
    }

    @Override
    protected AkpPublicJwk<PublicKey> createJwkFromKey(JwkContext<PublicKey> ctx) {
        PublicKey key = Assert.notNull(ctx.getKey(), "PublicKey cannot be null.");
        MlDsaAlgorithm alg = MlDsaAlgorithm.forKey(key);
        byte[] pub = alg.getPublicKeyMaterial(key);
        setAlgorithm(ctx, alg);
        put(ctx, DefaultAkpPublicJwk.PUB, pub);
        return new DefaultAkpPublicJwk<>(ctx);
    }

    @Override
    protected AkpPublicJwk<PublicKey> createJwkFromValues(JwkContext<PublicKey> ctx) {
        ParameterReadable reader = new RequiredParameterReader(ctx);
        MlDsaAlgorithm alg = getAlgorithm(reader);
        byte[] pub = reader.get(DefaultAkpPublicJwk.PUB);
        PublicKey key = alg.toPublicKey(pub, ctx.getProvider());
        ctx.setKey(key);
        return new DefaultAkpPublicJwk<>(ctx);
    }
}
