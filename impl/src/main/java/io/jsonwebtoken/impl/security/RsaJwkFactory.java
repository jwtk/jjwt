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
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.Jwk;

import java.security.Key;
import java.util.Set;

abstract class RsaJwkFactory<K extends Key, J extends Jwk<K>> extends AbstractFamilyJwkFactory<K, J> {

    RsaJwkFactory(String ktyValue, Class<K> keyType, Set<Field<?>> fields) {
        super(ktyValue, keyType, fields);
    }

    @Override
    protected String getKeyFactoryJcaName(final JwkContext<?> ctx) {
        String alg = KeysBridge.findAlgorithm(ctx.getKey());
        if (!Strings.hasText(alg) && // JWK from values because there's no existing key to inspect
                // See if it's RSA with sign/verify use and PSS is available:
                ctx.isSigUse() && RsaSignatureAlgorithm.isPssAvailable(ctx.getProvider())) {
            return RsaSignatureAlgorithm.PSS_JCA_NAME;
        }
        return super.getKeyFactoryJcaName(ctx);
    }
}
