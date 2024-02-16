/*
 * Copyright © 2024 jsonwebtoken.io
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

import io.jsonwebtoken.impl.io.Codec;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.impl.lang.Converters;

import java.math.BigInteger;

/**
 * Hotfix for <a href="https://github.com/jwtk/jjwt/issues/901">JJWT Issue 901</a>. This is currently hard-coded
 * expecting field elements for NIST P-256, P-384, or P-521 curves.  Ideally this should be refactored to work for
 * <em>any</em> curve based on its field size, not just for these NIST curves.  However, the
 * {@link EcPublicJwkFactory} and {@link EcPrivateJwkFactory} implementations only work with JWA NIST curves,
 * so this implementation is acceptable until (and if) different Weierstrass elliptic curves (ever) need to be
 * supported.
 *
 * @since 0.12.4
 */
final class FieldElementConverter implements Converter<BigInteger, byte[]> {

    static final FieldElementConverter INSTANCE = new FieldElementConverter();

    static final Converter<BigInteger, Object> B64URL_CONVERTER = Converters.forEncoded(BigInteger.class,
            Converters.compound(INSTANCE, Codec.BASE64URL));

    private static int bytelen(ECCurve curve) {
        return Bytes.length(curve.toParameterSpec().getCurve().getField().getFieldSize());
    }

    private static final int P256_BYTE_LEN = bytelen(ECCurve.P256);
    private static final int P384_BYTE_LEN = bytelen(ECCurve.P384);
    private static final int P521_BYTE_LEN = bytelen(ECCurve.P521);

    @Override
    public byte[] applyTo(BigInteger bigInteger) {
        byte[] bytes = Converters.BIGINT_UBYTES.applyTo(bigInteger);
        int len = bytes.length;
        if (len == P256_BYTE_LEN || len == P384_BYTE_LEN || len == P521_BYTE_LEN) return bytes;
        if (len < P256_BYTE_LEN) {
            bytes = Bytes.prepad(bytes, P256_BYTE_LEN);
        } else if (len < P384_BYTE_LEN) {
            bytes = Bytes.prepad(bytes, P384_BYTE_LEN);
        } else { // > P-384, so must be P-521:
            bytes = Bytes.prepad(bytes, P521_BYTE_LEN);
        }
        return bytes;
    }

    @Override
    public BigInteger applyFrom(byte[] bytes) {
        return Converters.BIGINT_UBYTES.applyFrom(bytes);
    }
}
