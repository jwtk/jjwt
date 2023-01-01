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

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.EcPublicJwk;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Set;

class DefaultEcPublicJwk extends AbstractPublicJwk<ECPublicKey> implements EcPublicJwk {

    static final String TYPE_VALUE = "EC";
    static final Field<String> CRV = Fields.string("crv", "Curve");
    static final Field<BigInteger> X = Fields.bigInt("x", "X Coordinate").build();
    static final Field<BigInteger> Y = Fields.bigInt("y", "Y Coordinate").build();
    static final Set<Field<?>> FIELDS = Collections.concat(AbstractAsymmetricJwk.FIELDS, CRV, X, Y);
    static final List<Field<?>> THUMBPRINT_FIELDS = Collections.<Field<?>>of(CRV, KTY, X, Y);

    DefaultEcPublicJwk(JwkContext<ECPublicKey> ctx) {
        super(ctx, THUMBPRINT_FIELDS);
    }
}
