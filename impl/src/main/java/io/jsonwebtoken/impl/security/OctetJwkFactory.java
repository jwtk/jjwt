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
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.security.Key;
import java.util.Set;

public abstract class OctetJwkFactory<K extends Key, J extends Jwk<K>> extends AbstractFamilyJwkFactory<K, J> {

    OctetJwkFactory(Class<K> keyType, Set<Field<?>> fields) {
        super(DefaultOctetPublicJwk.TYPE_VALUE, keyType, fields);
    }

    @Override
    public boolean supports(Key key) {
        return super.supports(key) && EdwardsCurve.isEdwards(key);
    }

    protected EdwardsCurve getCurve(final FieldReadable reader) throws UnsupportedKeyException {
        Field<String> field = DefaultOctetPublicJwk.CRV;
        String crvId = reader.get(field);
        EdwardsCurve curve = EdwardsCurve.findById(crvId);
        if (curve == null) {
            String msg = "Unrecognized OKP JWK " + field + " value '" + crvId + "'";
            throw new UnsupportedKeyException(msg);
        }
        return curve;
    }
}
