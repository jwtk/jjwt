package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.SignatureAlgorithms
import io.jsonwebtoken.security.UnsupportedKeyException
import org.junit.Test

import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.*

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
            String msg = "Unrecognized JWA curve id '$id'"
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testUnsupportedCurve() {
        EllipticCurve curve = AbstractEcJwkFactory.getJcaParameterSpec('secp128r1').getCurve()
        try {
            AbstractEcJwkFactory.getJwaIdByCurve(curve)
            fail()
        } catch (UnsupportedKeyException e) {
            assertEquals AbstractEcJwkFactory.UNSUPPORTED_CURVE_MSG, e.getMessage()
        }
    }

    @Test
    void testMultiplyInfinity() {
        ECParameterSpec spec = AbstractEcJwkFactory.getCurveByJwaId('P-256')
        def result = AbstractEcJwkFactory.multiply(ECPoint.POINT_INFINITY, BigInteger.valueOf(1), spec)
        assertEquals ECPoint.POINT_INFINITY, result
    }

    @Test
    void testDoubleInfinity() {
        ECParameterSpec spec = AbstractEcJwkFactory.getCurveByJwaId('P-256')
        def curve = spec.getCurve()
        def result = AbstractEcJwkFactory.doublePoint(ECPoint.POINT_INFINITY, curve)
        assertEquals ECPoint.POINT_INFINITY, result
    }

    @Test
    void testAddInfinity() {
        ECParameterSpec spec = AbstractEcJwkFactory.getCurveByJwaId('P-256')
        def curve = spec.getCurve()
        ECPoint point = new ECPoint(BigInteger.valueOf(1), BigInteger.valueOf(2)) // any point is fine for this test
        def result = AbstractEcJwkFactory.add(ECPoint.POINT_INFINITY, point, curve)
        //adding infinity to a point should return the point:
        assertEquals point, result
        //adding a point to infinity should return the point:
        result = AbstractEcJwkFactory.add(point, ECPoint.POINT_INFINITY, curve)
        assertEquals point, result
    }

    @Test
    void testAddSamePointDoublesIt() {
        def pair = SignatureAlgorithms.ES256.keyPairBuilder().build()
        def pub = pair.getPublic() as ECPublicKey

        def spec = pub.getParams()
        def curve = spec.getCurve()
        def point = pub.getW()

        def doubled = AbstractEcJwkFactory.doublePoint(point, curve)
        def added = AbstractEcJwkFactory.add(point, point, curve)
        assertEquals doubled, added
    }

    @Test
    void testDerivePublicFails() {

        def pair = SignatureAlgorithms.ES256.keyPairBuilder().build()
        def priv = pair.getPrivate() as ECPrivateKey

        final def context = new DefaultJwkContext(DefaultEcPrivateJwk.FIELDS)
        context.setKey(priv)

        def ex = new InvalidKeySpecException("invalid")

        def factory = new AbstractEcJwkFactory(ECPrivateKey.class) {
            @Override
            protected Jwk createJwkFromKey(JwkContext ctx) {
                return null
            }

            @Override
            protected Jwk createJwkFromValues(JwkContext ctx) {
                return null
            }

            @Override
            protected ECPublicKey derivePublic(KeyFactory keyFactory, ECPublicKeySpec spec) throws InvalidKeySpecException {
                throw ex
            }
        }

        try {
            factory.derivePublic(context)
            fail()
        } catch (UnsupportedKeyException expected) {
            String msg = 'Unable to derive ECPublicKey from ECPrivateKey: invalid'
            assertEquals msg, expected.getMessage()
        }
    }
}
