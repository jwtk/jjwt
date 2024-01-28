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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.UnsupportedKeyException
import org.junit.Test

import java.security.interfaces.ECPrivateKey

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class AbstractEcJwkFactoryTest {

    @Test
    void testInvalidJwaCurveId() {
        String id = 'foo'
        try {
            AbstractEcJwkFactory.getCurveByJwaId(id)
            fail()
        } catch (UnsupportedKeyException e) {
            String msg = "Unrecognized JWA EC curve id '$id'"
            assertEquals msg, e.getMessage()
        }
    }

    /**
     * Asserts correct behavior per https://github.com/jwtk/jjwt/issues/901
     * @since 0.12.4
     */
    @Test
    void fieldElementByteArrayLength() {

        EcSignatureAlgorithmTest.algs().each { alg ->

            def key = alg.keyPair().build().getPrivate() as ECPrivateKey
            def jwk = Jwks.builder().key(key).build()

            def json = Jwks.UNSAFE_JSON(jwk)
            def map = Services.get(Deserializer).deserialize(new StringReader(json)) as Map<String, ?>
            def xs = map.get("x") as String
            def ys = map.get("y") as String
            def ds = map.get("d") as String

            def x = Decoders.BASE64URL.decode(xs)
            def y = Decoders.BASE64URL.decode(ys)
            def d = Decoders.BASE64URL.decode(ds)

            // most important part of the test: 'x' and 'y' decoded byte arrays must have a length equal to the curve
            // field size (in bytes) per https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2 and
            // https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.3
            int fieldSizeInBits = key.getParams().getCurve().getField().getFieldSize()
            int fieldSizeInBytes = Bytes.length(fieldSizeInBits)
            assertEquals fieldSizeInBytes, x.length
            assertEquals fieldSizeInBytes, y.length

            // and 'd' must have a length equal to the curve order size in bytes per
            // https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2.1
            int orderSizeInBytes = Bytes.length(key.params.order.bitLength())
            assertEquals orderSizeInBytes, d.length
        }
    }
}
