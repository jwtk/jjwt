/*
 * Copyright © 2020 jsonwebtoken.io
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
import io.jsonwebtoken.impl.lang.FieldReadable;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.PublicJwk;
import io.jsonwebtoken.security.RsaPublicJwk;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Set;

class DefaultRsaPublicJwk extends AbstractPublicJwk<RSAPublicKey> implements RsaPublicJwk {

    static final String TYPE_VALUE = "RSA";
    static final Field<BigInteger> MODULUS = Fields.bigInt("n", "Modulus").build();
    static final Field<BigInteger> PUBLIC_EXPONENT = Fields.bigInt("e", "Public Exponent").build();
    static final Set<Field<?>> FIELDS = Collections.concat(AbstractAsymmetricJwk.FIELDS, MODULUS, PUBLIC_EXPONENT);

    // https://www.rfc-editor.org/rfc/rfc7638#section-3.2
    static final List<Field<?>> THUMBPRINT_FIELDS = Collections.<Field<?>>of(PUBLIC_EXPONENT, KTY, MODULUS);

    DefaultRsaPublicJwk(JwkContext<RSAPublicKey> ctx) {
        super(ctx, THUMBPRINT_FIELDS);
    }

    static boolean equalsPublic(FieldReadable self, Object candidate) {
        return Fields.equals(self, candidate, MODULUS) && Fields.equals(self, candidate, PUBLIC_EXPONENT);
    }

    @Override
    protected boolean equals(PublicJwk<?> jwk) {
        return jwk instanceof RsaPublicJwk && equalsPublic(this, jwk);
    }
}
