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
import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.AkpPublicJwk;
import io.jsonwebtoken.security.PublicJwk;

import java.security.PublicKey;
import java.util.List;
import java.util.Set;

public class DefaultAkpPublicJwk<T extends PublicKey> extends AbstractPublicJwk<T> implements AkpPublicJwk<T> {

    static final String TYPE_VALUE = "AKP";
    static final Parameter<byte[]> PUB = Parameters.bytes("pub", "The public key").build();
    static final Set<Parameter<?>> PARAMS = Collections.concat(AbstractAsymmetricJwk.PARAMS, PUB);

    // https://www.rfc-editor.org/rfc/rfc9964.html#name-akp-key-type - the required members for an AKP JWK
    // Thumbprint, in lexicographic order per https://www.rfc-editor.org/rfc/rfc7638#section-3.2:
    static final List<Parameter<?>> THUMBPRINT_PARAMS = Collections.<Parameter<?>>of(ALG, KTY, PUB);

    DefaultAkpPublicJwk(JwkContext<T> ctx) {
        super(ctx, THUMBPRINT_PARAMS);
    }

    static boolean equalsPublic(ParameterReadable self, Object candidate) {
        return Parameters.equals(self, candidate, ALG) && Parameters.equals(self, candidate, PUB);
    }

    @Override
    protected boolean equals(PublicJwk<?> jwk) {
        return jwk instanceof AkpPublicJwk && equalsPublic(this, jwk);
    }
}
