/*
 * Copyright (C) 2020 jsonwebtoken.io
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

import io.jsonwebtoken.security.EcPrivateJwk
import io.jsonwebtoken.security.EcPublicJwk
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.UnsupportedKeyException
import org.junit.Test

import java.security.Key
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

import static org.junit.Assert.*

class DispatchingJwkFactoryTest {

    @Test(expected = IllegalArgumentException)
    void testNullJwk() {
        new DispatchingJwkFactory().createJwk(null)
    }

    @Test(expected = InvalidKeyException)
    void testEmptyJwk() {
        new DispatchingJwkFactory().createJwk(new DefaultJwkContext<Key>())
    }

    @Test(expected = UnsupportedKeyException)
    void testUnknownKtyValue() {
        def ctx = new DefaultJwkContext()
        ctx.put('kty', 'foo')
        new DispatchingJwkFactory().createJwk(ctx)
    }

    @Test
    void testNewContextNoFamily() {
        def ctx = new DefaultJwkContext()
        def key = new TestKey(algorithm: 'foo')
        try {
            DispatchingJwkFactory.DEFAULT_INSTANCE.newContext(ctx, key)
            fail()
        } catch (UnsupportedKeyException uke) {
            String msg = 'Unable to create JWK for unrecognized key of type io.jsonwebtoken.impl.security.TestKey: ' +
                    'there is no known JWK Factory capable of creating JWKs for this key type.'
            assertEquals msg, uke.getMessage()
        }
    }

    @Test
    void testUnknownKeyType() {
        def key = new Key() {
            @Override
            String getAlgorithm() {
                return null
            }

            @Override
            String getFormat() {
                return null
            }

            @Override
            byte[] getEncoded() {
                return new byte[0]
            }
        }
        def ctx = new DefaultJwkContext().setKey(key)
        try {
            new DispatchingJwkFactory().createJwk(ctx)
            fail()
        } catch (UnsupportedKeyException uke) {
            String msg = 'Unable to create JWK for unrecognized key of type io.jsonwebtoken.impl.security.DispatchingJwkFactoryTest$1: there is no known JWK Factory capable of creating JWKs for this key type.'
            assertEquals msg, uke.getMessage()
        }
    }

    @Test
    void testEcKeyPairToKey() {

        Map<String, String> m = [
                'kty': 'EC',
                'crv': 'P-256',
                "x"  : "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                "y"  : "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
                "d"  : "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
        ]

        def ctx = new DefaultJwkContext()
        ctx.putAll(m)

        DispatchingJwkFactory factory = new DispatchingJwkFactory()
        ctx = factory.newContext(ctx, null)

        def jwk = factory.createJwk(ctx) as EcPrivateJwk
        assertTrue jwk instanceof EcPrivateJwk
        def key = jwk.toKey()
        assertTrue key instanceof ECPrivateKey
        String x = AbstractEcJwkFactory.toOctetString(key.params.curve.field.fieldSize, jwk.toPublicJwk().toKey().w.affineX)
        String y = AbstractEcJwkFactory.toOctetString(key.params.curve.field.fieldSize, jwk.toPublicJwk().toKey().w.affineY)
        String d = AbstractEcJwkFactory.toOctetString(key.params.curve.field.fieldSize, key.s)
        assertEquals jwk.d.get(), d

        //remove the 'd' mapping to represent only a public key:
        m.remove(DefaultEcPrivateJwk.D.getId())
        ctx = new DefaultJwkContext()
        ctx.putAll(m)
        ctx = factory.newContext(ctx, null)

        jwk = factory.createJwk(ctx) as EcPublicJwk
        assertTrue jwk instanceof EcPublicJwk
        key = jwk.toKey() as ECPublicKey
        assertTrue key instanceof ECPublicKey
        assertEquals jwk.x, x
        assertEquals jwk.y, y
    }
}
