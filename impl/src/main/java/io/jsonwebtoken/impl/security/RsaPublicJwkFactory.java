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

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.impl.lang.RequiredParameterReader;
import io.jsonwebtoken.security.RsaPublicJwk;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

class RsaPublicJwkFactory extends AbstractFamilyJwkFactory<RSAPublicKey, RsaPublicJwk> {

    static final RsaPublicJwkFactory INSTANCE = new RsaPublicJwkFactory();

    RsaPublicJwkFactory() {
        super(DefaultRsaPublicJwk.TYPE_VALUE, RSAPublicKey.class, DefaultRsaPublicJwk.PARAMS);
    }

    @Override
    protected RsaPublicJwk createJwkFromKey(JwkContext<RSAPublicKey> ctx) {
        RSAPublicKey key = ctx.getKey();
        ctx.put(DefaultRsaPublicJwk.MODULUS.getId(), DefaultRsaPublicJwk.MODULUS.applyTo(key.getModulus()));
        ctx.put(DefaultRsaPublicJwk.PUBLIC_EXPONENT.getId(), DefaultRsaPublicJwk.PUBLIC_EXPONENT.applyTo(key.getPublicExponent()));
        return new DefaultRsaPublicJwk(ctx);
    }

    @Override
    protected RsaPublicJwk createJwkFromValues(JwkContext<RSAPublicKey> ctx) {
        ParameterReadable reader = new RequiredParameterReader(ctx);
        BigInteger modulus = reader.get(DefaultRsaPublicJwk.MODULUS);
        BigInteger publicExponent = reader.get(DefaultRsaPublicJwk.PUBLIC_EXPONENT);
        final RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);

        RSAPublicKey key = generateKey(ctx, new CheckedFunction<KeyFactory, RSAPublicKey>() {
            @Override
            public RSAPublicKey apply(KeyFactory keyFactory) throws Exception {
                return (RSAPublicKey) keyFactory.generatePublic(spec);
            }
        });

        ctx.setKey(key);

        return new DefaultRsaPublicJwk(ctx);
    }
}
