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

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test

import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPublicKeySpec
import java.security.spec.InvalidKeySpecException

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class EcPrivateJwkFactoryTest {

    @Test
    void testDMissing() {
        def values = ['kty': 'EC', 'crv': 'P-256', 'x': BigInteger.ONE, 'y': BigInteger.ONE]
        try {
            def ctx = new DefaultJwkContext(DefaultEcPrivateJwk.PARAMS)
            ctx.putAll(values)
            new EcPrivateJwkFactory().createJwkFromValues(ctx)
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "EC JWK is missing required 'd' (ECC Private Key) value."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testDerivePublicFails() {

        def pair = Jwts.SIG.ES256.keyPair().build()
        def priv = pair.getPrivate() as ECPrivateKey

        final def context = new DefaultJwkContext(DefaultEcPrivateJwk.PARAMS)
        context.setKey(priv)

        def ex = new InvalidKeySpecException("invalid")

        def factory = new EcPrivateJwkFactory() {
            @Override
            protected ECPublicKey derivePublic(KeyFactory keyFactory, ECPublicKeySpec spec) throws InvalidKeySpecException {
                throw ex
            }
        }

        try {
            factory.derivePublic(context)
            fail()
        } catch (InvalidKeyException expected) {
            String msg = 'Unable to derive ECPublicKey from ECPrivateKey: invalid'
            assertEquals msg, expected.getMessage()
        }
    }
}
