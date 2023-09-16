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

import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test

import java.security.spec.EllipticCurve

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class EcPublicJwkFactoryTest {

    @Test
    void testCurveMissing() {
        try {
            Jwks.builder().add(['kty': 'EC']).build()
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "EC JWK is missing required 'crv' (Curve) value."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testXMissing() {
        try {
            Jwks.builder().add(['kty': 'EC', 'crv': 'P-256']).build()
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "EC JWK is missing required 'x' (X Coordinate) value."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testYMissing() {
        try {
            String encoded = DefaultEcPublicJwk.X.applyTo(BigInteger.ONE)
            Jwks.builder().add(['kty': 'EC', 'crv': 'P-256', 'x': encoded]).build()
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "EC JWK is missing required 'y' (Y Coordinate) value."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testPointNotOnCurve() {
        try {
            String encoded = DefaultEcPublicJwk.X.applyTo(BigInteger.ONE)
            Jwks.builder().add(['kty': 'EC', 'crv': 'P-256', 'x': encoded, 'y': encoded]).build()
            fail()
        } catch (InvalidKeyException expected) {
            String msg = "EC JWK x,y coordinates do not exist on elliptic curve 'P-256'. " +
                    "This could be due simply to an incorrectly-created JWK or possibly an attempted " +
                    "Invalid Curve Attack (see https://safecurves.cr.yp.to/twist.html for more information)."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testUnsupportedCurve() {
        def curve = new EllipticCurve(new TestECField(fieldSize: 1), BigInteger.ONE, BigInteger.TEN)
        try {
            EcPublicJwkFactory.getJwaIdByCurve(curve)
            fail()
        } catch (InvalidKeyException e) {
            assertEquals EcPublicJwkFactory.UNSUPPORTED_CURVE_MSG, e.getMessage()
        }
    }
}
