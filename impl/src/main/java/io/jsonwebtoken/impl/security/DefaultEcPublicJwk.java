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
import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.EcPublicJwk;
import io.jsonwebtoken.security.PublicJwk;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Set;

class DefaultEcPublicJwk extends AbstractPublicJwk<ECPublicKey> implements EcPublicJwk {

    static final String TYPE_VALUE = "EC";
    static final Parameter<String> CRV = Parameters.string("crv", "Curve");
    static final Parameter<BigInteger> X = Parameters.bigInt("x", "X Coordinate").build();
    static final Parameter<BigInteger> Y = Parameters.bigInt("y", "Y Coordinate").build();
    static final Set<Parameter<?>> PARAMS = Collections.concat(AbstractAsymmetricJwk.PARAMS, CRV, X, Y);

    // https://www.rfc-editor.org/rfc/rfc7638#section-3.2
    static final List<Parameter<?>> THUMBPRINT_PARAMS = Collections.<Parameter<?>>of(CRV, KTY, X, Y);

    DefaultEcPublicJwk(JwkContext<ECPublicKey> ctx) {
        super(ctx, THUMBPRINT_PARAMS);
    }

    static boolean equalsPublic(ParameterReadable self, Object candidate) {
        return Parameters.equals(self, candidate, CRV) &&
                Parameters.equals(self, candidate, X) &&
                Parameters.equals(self, candidate, Y);
    }

    @Override
    protected boolean equals(PublicJwk<?> jwk) {
        return jwk instanceof EcPublicJwk && equalsPublic(this, jwk);
    }
}
