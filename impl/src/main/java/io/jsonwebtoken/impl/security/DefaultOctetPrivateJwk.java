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
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.OctetPrivateJwk;
import io.jsonwebtoken.security.OctetPublicJwk;
import io.jsonwebtoken.security.PrivateJwk;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;

import static io.jsonwebtoken.impl.security.DefaultOctetPublicJwk.equalsPublic;

public class DefaultOctetPrivateJwk<T extends PrivateKey, P extends PublicKey>
        extends AbstractPrivateJwk<T, P, OctetPublicJwk<P>> implements OctetPrivateJwk<T, P> {

    static final Field<byte[]> D = Fields.bytes("d", "The private key").setSecret(true).build();

    static final Set<Field<?>> FIELDS = Collections.concat(DefaultOctetPublicJwk.FIELDS, D);

    DefaultOctetPrivateJwk(JwkContext<T> ctx, OctetPublicJwk<P> pubJwk) {
        super(ctx,
                // only public members are included in Private JWK Thumbprints per
                // https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
                DefaultOctetPublicJwk.THUMBPRINT_FIELDS, pubJwk);
    }

    @Override
    protected boolean equals(PrivateJwk<?, ?, ?> jwk) {
        return jwk instanceof OctetPrivateJwk && equalsPublic(this, jwk) && Fields.equals(this, jwk, D);
    }
}
