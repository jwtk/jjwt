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
import io.jsonwebtoken.security.EcPrivateJwk;
import io.jsonwebtoken.security.EcPublicJwk;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

class DefaultEcPrivateJwk extends AbstractPrivateJwk<ECPrivateKey, ECPublicKey, EcPublicJwk> implements EcPrivateJwk {

    static final Field<BigInteger> D = Fields.secretBigInt("d", "ECC Private Key");
    static final Set<Field<?>> FIELDS = Collections.concat(DefaultEcPublicJwk.FIELDS, D);

    DefaultEcPrivateJwk(JwkContext<ECPrivateKey> ctx, EcPublicJwk pubJwk) {
        super(ctx,
                // only public members are included in Private JWK Thumbprints per
                // https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
                DefaultEcPublicJwk.THUMBPRINT_FIELDS,
                pubJwk);
    }
}
