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

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.FieldReadable;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.OctetPublicJwk;
import io.jsonwebtoken.security.PublicJwk;

import java.security.PublicKey;
import java.util.List;
import java.util.Set;

public class DefaultOctetPublicJwk<T extends PublicKey> extends AbstractPublicJwk<T> implements OctetPublicJwk<T> {

    static final String TYPE_VALUE = "OKP";
    static final Field<String> CRV = DefaultEcPublicJwk.CRV;
    static final Field<byte[]> X = Fields.bytes("x", "The public key").build();
    static final Set<Field<?>> FIELDS = Collections.concat(AbstractAsymmetricJwk.FIELDS, CRV, X);

    // https://www.rfc-editor.org/rfc/rfc8037#section-2 (last paragraph):
    static final List<Field<?>> THUMBPRINT_FIELDS = Collections.<Field<?>>of(CRV, KTY, X);

    DefaultOctetPublicJwk(JwkContext<T> ctx) {
        super(ctx, THUMBPRINT_FIELDS);
    }

    static boolean equalsPublic(FieldReadable self, Object candidate) {
        return Fields.equals(self, candidate, CRV) && Fields.equals(self, candidate, X);
    }

    @Override
    protected boolean equals(PublicJwk<?> jwk) {
        return jwk instanceof OctetPublicJwk && equalsPublic(this, jwk);
    }
}
