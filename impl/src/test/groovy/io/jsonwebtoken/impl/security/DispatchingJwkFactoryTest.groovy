package io.jsonwebtoken.impl.security

import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.EcPrivateJwk
import io.jsonwebtoken.security.EcPublicJwk
import io.jsonwebtoken.security.SignatureAlgorithms
import io.jsonwebtoken.security.UnsupportedKeyException
import org.junit.Ignore
import org.junit.Test

import java.security.Key
import java.security.KeyPair
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

import static org.junit.Assert.*

class DispatchingJwkFactoryTest {

    @Test(expected = IllegalArgumentException)
    void testNullJwk() {
        new DispatchingJwkFactory().createJwk(null)
    }

    @Test(expected = IllegalArgumentException)
    void testEmptyJwk() {
        new DispatchingJwkFactory().createJwk(new DefaultJwkContext<Key>())
    }

    @Test(expected = UnsupportedKeyException)
    void testUnknownKeyType() {
        def ctx = new DefaultJwkContext();
        ctx.put('kty', 'foo')
        new DispatchingJwkFactory().createJwk(ctx)
    }

    @Test
    void testEcKeyPairToKey() {

        Map<String,String> m = [
                'kty': 'EC',
                'crv': 'P-256',
                "x"  : "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                "y"  : "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
                "d"  : "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
        ]

        def ctx = new DefaultJwkContext()
        ctx.putAll(m)

        DispatchingJwkFactory factory = new DispatchingJwkFactory()

        def jwk = factory.createJwk(ctx) as EcPrivateJwk
        assertTrue jwk instanceof EcPrivateJwk
        def key = jwk.toKey()
        assertTrue key instanceof ECPrivateKey
        String x = AbstractEcJwkFactory.toOctetString(key.params.curve.field.fieldSize, jwk.toPublicJwk().toKey().w.affineX)
        String y = AbstractEcJwkFactory.toOctetString(key.params.curve.field.fieldSize, jwk.toPublicJwk().toKey().w.affineY)
        String d = AbstractEcJwkFactory.toOctetString(key.params.curve.field.fieldSize, key.s)
        assertEquals jwk.d, d

        //remove the 'd' mapping to represent only a public key:
        m.remove(DefaultEcPrivateJwk.D)
        ctx = new DefaultJwkContext()
        ctx.putAll(m)

        jwk = factory.createJwk(ctx) as EcPublicJwk
        assertTrue jwk instanceof EcPublicJwk
        key = jwk.toKey() as ECPublicKey
        assertTrue key instanceof ECPublicKey
        assertEquals jwk.x, x
        assertEquals jwk.y, y
    }

    @Test
    @Ignore
    //TODO re-enable
    void testEcKeyPairToJwk() {

        KeyPair pair = SignatureAlgorithms.ES256.generateKeyPair()
        ECPublicKey pubKey = (ECPublicKey) pair.getPublic()
        def ctx = new DefaultJwkContext()
        ctx.setKey(pubKey)

        DispatchingJwkFactory factory = new DispatchingJwkFactory()

        def jwk = factory.createJwk(ctx)

        assertNotNull jwk
        assertEquals "EC", jwk.kty
        assertEquals Encoders.BASE64URL.encode(pubKey.w.affineX.toByteArray()), jwk.x
        assertEquals Encoders.BASE64URL.encode(pubKey.w.affineY.toByteArray()), jwk.y
        assertNull jwk.d //public keys should not populate the private key 'd' parameter
    }
}
