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

import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.AkpPrivateJwk;
import io.jsonwebtoken.security.AkpPublicJwk;
import io.jsonwebtoken.security.PrivateJwk;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;

import static io.jsonwebtoken.impl.security.DefaultAkpPublicJwk.equalsPublic;

public class DefaultAkpPrivateJwk<T extends PrivateKey, P extends PublicKey>
        extends AbstractPrivateJwk<T, P, AkpPublicJwk<P>> implements AkpPrivateJwk<T, P> {

    /**
     * Per RFC 9964, Section 6, the {@code priv} value of an ML-DSA AKP JWK is the 32-byte private key seed.
     */
    static final Parameter<byte[]> PRIV = Parameters.bytes("priv", "The private key").setSecret(true).build();

    static final Set<Parameter<?>> PARAMS = Collections.concat(DefaultAkpPublicJwk.PARAMS, PRIV);

    DefaultAkpPrivateJwk(JwkContext<T> ctx, AkpPublicJwk<P> pubJwk) {
        super(ctx,
                // only public members are included in Private JWK Thumbprints per
                // https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
                DefaultAkpPublicJwk.THUMBPRINT_PARAMS, pubJwk);
    }

    @Override
    protected boolean equals(PrivateJwk<?, ?, ?> jwk) {
        return jwk instanceof AkpPrivateJwk && equalsPublic(this, jwk) && Parameters.equals(this, jwk, PRIV);
    }
}
