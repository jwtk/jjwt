/*
 * Copyright (C) 2022 jsonwebtoken.io
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
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.SecretJwk;

import javax.crypto.SecretKey;
import java.util.List;
import java.util.Set;

class DefaultSecretJwk extends AbstractJwk<SecretKey> implements SecretJwk {

    static final String TYPE_VALUE = "oct";
    static final Parameter<byte[]> K = Parameters.bytes("k", "Key Value").setSecret(true).build();
    static final Set<Parameter<?>> PARAMS = Collections.concat(AbstractJwk.PARAMS, K);

    // https://www.rfc-editor.org/rfc/rfc7638#section-3.2
    static final List<Parameter<?>> THUMBPRINT_PARAMS = Collections.<Parameter<?>>of(K, KTY);

    DefaultSecretJwk(JwkContext<SecretKey> ctx) {
        super(ctx, THUMBPRINT_PARAMS);
    }

    @Override
    protected boolean equals(Jwk<?> jwk) {
        return jwk instanceof SecretJwk && Parameters.equals(this, jwk, K);
    }
}
