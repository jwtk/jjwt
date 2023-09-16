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

import io.jsonwebtoken.impl.lang.Converters;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.ECKey;
import java.util.Set;

abstract class AbstractEcJwkFactory<K extends Key & ECKey, J extends Jwk<K>> extends AbstractFamilyJwkFactory<K, J> {

    protected static ECCurve getCurveByJwaId(String jwaCurveId) {
        ECCurve curve = ECCurve.findById(jwaCurveId);
        if (curve == null) {
            String msg = "Unrecognized JWA EC curve id '" + jwaCurveId + "'";
            throw new UnsupportedKeyException(msg);
        }
        return curve;
    }

    /**
     * https://tools.ietf.org/html/rfc7518#section-6.2.1.2 indicates that this algorithm logic is defined in
     * http://www.secg.org/sec1-v2.pdf Section 2.3.5.
     *
     * @param fieldSize  EC field size
     * @param coordinate EC point coordinate (e.g. x or y)
     * @return A base64Url-encoded String representing the EC field element per the RFC format
     */
    // Algorithm defined in http://www.secg.org/sec1-v2.pdf Section 2.3.5
    static String toOctetString(int fieldSize, BigInteger coordinate) {
        byte[] bytes = Converters.BIGINT_UBYTES.applyTo(coordinate);
        int mlen = (int) Math.ceil(fieldSize / 8d);
        if (mlen > bytes.length) {
            byte[] m = new byte[mlen];
            System.arraycopy(bytes, 0, m, mlen - bytes.length, bytes.length);
            bytes = m;
        }
        return Encoders.BASE64URL.encode(bytes);
    }

    AbstractEcJwkFactory(Class<K> keyType, Set<Parameter<?>> params) {
        super(DefaultEcPublicJwk.TYPE_VALUE, keyType, params);
    }
}
