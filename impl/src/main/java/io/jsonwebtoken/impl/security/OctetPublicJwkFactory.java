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

import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.impl.lang.RequiredParameterReader;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.OctetPublicJwk;

import java.security.PublicKey;

public class OctetPublicJwkFactory extends OctetJwkFactory<PublicKey, OctetPublicJwk<PublicKey>> {

    static final OctetPublicJwkFactory INSTANCE = new OctetPublicJwkFactory();

    OctetPublicJwkFactory() {
        super(PublicKey.class, DefaultOctetPublicJwk.PARAMS);
    }

    @Override
    protected OctetPublicJwk<PublicKey> createJwkFromKey(JwkContext<PublicKey> ctx) {
        PublicKey key = Assert.notNull(ctx.getKey(), "PublicKey cannot be null.");
        EdwardsCurve crv = EdwardsCurve.forKey(key);
        byte[] x = crv.getKeyMaterial(key);
        Assert.notEmpty(x, "Edwards PublicKey 'x' value cannot be null or empty.");
        //TODO: assert that the curve contains the specified key
        put(ctx, DefaultOctetPublicJwk.CRV, crv.getId());
        put(ctx, DefaultOctetPublicJwk.X, x);
        return new DefaultOctetPublicJwk<>(ctx);
    }

    @Override
    protected OctetPublicJwk<PublicKey> createJwkFromValues(JwkContext<PublicKey> ctx) {
        ParameterReadable reader = new RequiredParameterReader(ctx);
        EdwardsCurve curve = getCurve(reader);
        byte[] x = reader.get(DefaultOctetPublicJwk.X);
        //TODO: assert that the curve contains the specified key
        PublicKey key = curve.toPublicKey(x, ctx.getProvider());
        ctx.setKey(key);
        return new DefaultOctetPublicJwk<>(ctx);
    }
}
