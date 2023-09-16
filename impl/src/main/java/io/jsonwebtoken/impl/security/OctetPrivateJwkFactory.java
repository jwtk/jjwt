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
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.OctetPrivateJwk;
import io.jsonwebtoken.security.OctetPublicJwk;

import java.security.PrivateKey;
import java.security.PublicKey;

public class OctetPrivateJwkFactory extends OctetJwkFactory<PrivateKey, OctetPrivateJwk<PrivateKey, PublicKey>> {

    public OctetPrivateJwkFactory() {
        super(PrivateKey.class, DefaultOctetPrivateJwk.PARAMS);
    }

    @Override
    protected boolean supportsKeyValues(JwkContext<?> ctx) {
        return super.supportsKeyValues(ctx) && ctx.containsKey(DefaultOctetPrivateJwk.D.getId());
    }

    @Override
    protected OctetPrivateJwk<PrivateKey, PublicKey> createJwkFromKey(JwkContext<PrivateKey> ctx) {
        PrivateKey key = Assert.notNull(ctx.getKey(), "PrivateKey cannot be null.");
        EdwardsCurve crv = EdwardsCurve.forKey(key);

        PublicKey pub = ctx.getPublicKey();
        if (pub != null) {
            if (!crv.equals(EdwardsCurve.forKey(pub))) {
                String msg = "Specified Edwards Curve PublicKey does not match the specified PrivateKey's curve.";
                throw new InvalidKeyException(msg);
            }
        } else { // not supplied - try to generate it:
            pub = EdwardsCurve.derivePublic(key);
        }

        // If a JWK fingerprint has been requested to be the JWK id, ensure we copy over the one computed for the
        // public key per https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
        boolean copyId = !Strings.hasText(ctx.getId()) && ctx.getIdThumbprintAlgorithm() != null;
        JwkContext<PublicKey> pubCtx = OctetPublicJwkFactory.INSTANCE.newContext(ctx, pub);
        OctetPublicJwk<PublicKey> pubJwk = OctetPublicJwkFactory.INSTANCE.createJwk(pubCtx);
        ctx.putAll(pubJwk);
        if (copyId) {
            ctx.setId(pubJwk.getId());
        }

        //now add the d value
        byte[] d = crv.getKeyMaterial(key);
        Assert.notEmpty(d, "Edwards PrivateKey 'd' value cannot be null or empty.");
        //TODO: assert that the curve contains the specified key
        put(ctx, DefaultOctetPrivateJwk.D, d);

        return new DefaultOctetPrivateJwk<>(ctx, pubJwk);
    }

    @Override
    protected OctetPrivateJwk<PrivateKey, PublicKey> createJwkFromValues(JwkContext<PrivateKey> ctx) {
        ParameterReadable reader = new RequiredParameterReader(ctx);
        EdwardsCurve curve = getCurve(reader);
        //TODO: assert that the curve contains the specified key

        // public values are required, so assert them:
        JwkContext<PublicKey> pubCtx = new DefaultJwkContext<>(DefaultOctetPublicJwk.PARAMS, ctx);
        OctetPublicJwk<PublicKey> pubJwk = OctetPublicJwkFactory.INSTANCE.createJwkFromValues(pubCtx);

        byte[] d = reader.get(DefaultOctetPrivateJwk.D);
        PrivateKey key = curve.toPrivateKey(d, ctx.getProvider());
        ctx.setKey(key);

        return new DefaultOctetPrivateJwk<>(ctx, pubJwk);
    }
}
