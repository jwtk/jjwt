package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class EcPublicJwkFactoryTest {

    @Test
    void testCurveMissing() {
        try {
            Jwks.builder().putAll(['kty': 'EC']).build()
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "EC JWK is missing required 'crv' (Curve) value."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testXMissing() {
        try {
            Jwks.builder().putAll(['kty': 'EC', 'crv': 'P-256']).build()
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "EC JWK is missing required 'x' (X Coordinate) value."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testYMissing() {
        try {
            Jwks.builder().putAll(['kty': 'EC', 'crv': 'P-256', 'x': BigInteger.ONE]).build()
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "EC JWK is missing required 'y' (Y Coordinate) value."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testPointNotOnCurve() {
        try {
            Jwks.builder().putAll(['kty': 'EC', 'crv': 'P-256', 'x': BigInteger.ONE, 'y': BigInteger.ONE]).build()
            fail()
        } catch (InvalidKeyException expected) {
            String msg = "EC JWK x,y coordinates do not exist on elliptic curve 'P-256'. " +
                    "This could be due simply to an incorrectly-created JWK or possibly an attempted " +
                    "Invalid Curve Attack (see https://safecurves.cr.yp.to/twist.html for more information)."
            assertEquals msg, expected.getMessage()
        }
    }
}
