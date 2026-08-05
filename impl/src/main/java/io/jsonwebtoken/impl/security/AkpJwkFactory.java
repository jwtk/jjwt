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
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.security.Key;
import java.util.Set;

/**
 * Base {@link FamilyJwkFactory} for the {@code AKP} key type defined by
 * <a href="https://www.rfc-editor.org/rfc/rfc9964.html#name-akp-key-type">RFC 9964, Section 5</a>.
 *
 * @since 0.14.0
 */
abstract class AkpJwkFactory<K extends Key, J extends Jwk<K>> extends AbstractFamilyJwkFactory<K, J> {

    AkpJwkFactory(Class<K> keyType, Set<Parameter<?>> params) {
        super(DefaultAkpPublicJwk.TYPE_VALUE, keyType, params);
    }

    @Override
    public boolean supports(Key key) {
        return super.supports(key) && MlDsaAlgorithm.isMlDsa(key);
    }

    /**
     * Returns the ML-DSA parameter set identified by the JWK's required {@code alg} value.
     */
    protected static MlDsaAlgorithm getAlgorithm(final ParameterReadable reader) throws UnsupportedKeyException {
        // RFC 9964, Section 5: 'alg' is a REQUIRED member of an AKP JWK, since the key material has no meaning
        // without knowing the algorithm that produced it:
        String alg = reader.get(AbstractJwk.ALG);
        return MlDsaAlgorithm.forId(alg);
    }

    /**
     * Ensures the JWK's {@code alg} value reflects the specified key's ML-DSA parameter set, setting it if absent
     * and rejecting it if it contradicts the key.
     */
    protected static void setAlgorithm(JwkContext<?> ctx, MlDsaAlgorithm alg) throws InvalidKeyException {
        String existing = Strings.clean(ctx.getAlgorithm());
        if (existing == null) {
            ctx.setAlgorithm(alg.getId());
        } else if (!existing.equals(alg.getId())) {
            String msg = "AKP JWK 'alg' value '" + existing + "' does not equal the specified key's ML-DSA " +
                    "parameter set '" + alg.getId() + "'.";
            throw new InvalidKeyException(msg);
        }
    }
}
