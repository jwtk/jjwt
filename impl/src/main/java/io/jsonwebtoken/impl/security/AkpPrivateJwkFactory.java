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
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.AkpPrivateJwk;
import io.jsonwebtoken.security.AkpPublicJwk;
import io.jsonwebtoken.security.InvalidKeyException;

import java.security.PrivateKey;
import java.security.PublicKey;

public class AkpPrivateJwkFactory extends AkpJwkFactory<PrivateKey, AkpPrivateJwk<PrivateKey, PublicKey>> {

    public AkpPrivateJwkFactory() {
        super(PrivateKey.class, DefaultAkpPrivateJwk.PARAMS);
    }

    @Override
    protected boolean supportsKeyValues(JwkContext<?> ctx) {
        return super.supportsKeyValues(ctx) && ctx.containsKey(DefaultAkpPrivateJwk.PRIV.getId());
    }

    @Override
    protected AkpPrivateJwk<PrivateKey, PublicKey> createJwkFromKey(JwkContext<PrivateKey> ctx) {

        PrivateKey key = Assert.notNull(ctx.getKey(), "PrivateKey cannot be null.");
        MlDsaAlgorithm alg = MlDsaAlgorithm.forKey(key);
        setAlgorithm(ctx, alg);

        PublicKey pub = ctx.getPublicKey();
        if (pub == null) {
            // Unlike RSA, Elliptic Curve and Edwards keys, an ML-DSA public key cannot be derived from a private key
            // through the JCA: FIPS 204 public key derivation requires expanding the seed, which no standard JCA API
            // exposes.  The caller must therefore supply the matching public key.
            String msg = "Unable to derive an ML-DSA PublicKey from the specified PrivateKey: the JCA does not " +
                    "expose ML-DSA public key derivation.  Please specify the matching PublicKey when building an " +
                    "AKP private JWK, for example Jwks.builder().key(privateKey).publicKey(publicKey).build().";
            throw new InvalidKeyException(msg);
        }
        if (!alg.equals(MlDsaAlgorithm.forKey(pub))) {
            String msg = "Specified ML-DSA PublicKey parameter set does not match the specified PrivateKey's " +
                    "parameter set.";
            throw new InvalidKeyException(msg);
        }

        // RFC 9964, Section 6: 'priv' MUST be the 32-byte seed:
        byte[] priv = alg.getSeed(key);

        // If a JWK fingerprint has been requested to be the JWK id, ensure we copy over the one computed for the
        // public key per https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
        boolean copyId = !Strings.hasText(ctx.getId()) && ctx.getIdThumbprintAlgorithm() != null;
        JwkContext<PublicKey> pubCtx = AkpPublicJwkFactory.INSTANCE.newContext(ctx, pub);
        AkpPublicJwk<PublicKey> pubJwk = AkpPublicJwkFactory.INSTANCE.createJwk(pubCtx);
        ctx.putAll(pubJwk);
        if (copyId) {
            ctx.setId(pubJwk.getId());
        }

        put(ctx, DefaultAkpPrivateJwk.PRIV, priv);

        return new DefaultAkpPrivateJwk<>(ctx, pubJwk);
    }

    @Override
    protected AkpPrivateJwk<PrivateKey, PublicKey> createJwkFromValues(JwkContext<PrivateKey> ctx) {

        ParameterReadable reader = new RequiredParameterReader(ctx);
        MlDsaAlgorithm alg = getAlgorithm(reader);

        // public values are required per RFC 9964, Section 5, so assert them:
        JwkContext<PublicKey> pubCtx = new DefaultJwkContext<>(DefaultAkpPublicJwk.PARAMS, ctx);
        AkpPublicJwk<PublicKey> pubJwk = AkpPublicJwkFactory.INSTANCE.createJwkFromValues(pubCtx);

        byte[] priv = reader.get(DefaultAkpPrivateJwk.PRIV);
        PrivateKey key = alg.toPrivateKey(priv, ctx.getProvider());
        ctx.setKey(key);

        return new DefaultAkpPrivateJwk<>(ctx, pubJwk);
    }
}
