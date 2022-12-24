package io.jsonwebtoken.impl.security

import org.junit.Test

import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint

import static org.junit.Assert.assertFalse
import static org.junit.Assert.assertTrue

class ECCurveTest {

    @Test
    void testContainsTrue() {
        ECCurve curve = (ECCurve) Curves.P_256
        def pair = curve.keyPairBuilder().build()
        ECPublicKey ecPub = (ECPublicKey) pair.getPublic()
        assertTrue(curve.contains(ecPub.getW()))
    }

    @Test
    void testContainsFalse() {
        assertFalse(((ECCurve) Curves.P_256).contains(new ECPoint(BigInteger.ONE, BigInteger.ONE)))
    }
}
