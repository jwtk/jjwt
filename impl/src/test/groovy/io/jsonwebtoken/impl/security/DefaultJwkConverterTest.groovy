package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.SignatureAlgorithms
import io.jsonwebtoken.security.UnsupportedKeyException
import org.junit.Ignore

import java.security.KeyPair
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

import static org.junit.Assert.*

import io.jsonwebtoken.io.Encoders
import org.junit.Test

class DefaultJwkConverterTest {

    @Test
    void testNullJwk() {
        try {
            new DefaultJwkConverter().toKey(null)
            fail()
        } catch (InvalidKeyException expected) {
            assertEquals 'JWK map cannot be null or empty.', expected.message
        }
    }

    @Test
    void testEmptyJwk() {
        try {
            new DefaultJwkConverter().toKey([:])
            fail()
        } catch (InvalidKeyException expected) {
            assertEquals 'JWK map cannot be null or empty.', expected.message
        }
    }

    @Test
    void testUnknownKeyType() {

        def jwk = [
                'kty': 'foo'
        ]

        DefaultJwkConverter converter = new DefaultJwkConverter()
        try {
            converter.toKey(jwk)
            fail()
        } catch (UnsupportedKeyException e) {
            assertEquals 'Unrecognized JWK kty (key type) value: foo', e.getMessage()
        }
    }

    @Test
    void testEcKeyPairToKey() {

        def jwk = [
                'kty': 'EC',
                'crv': 'P-256',
                "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
                "d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
        ]

        DefaultJwkConverter converter = new DefaultJwkConverter()

        def key = converter.toKey(jwk)
        assertTrue key instanceof ECPrivateKey
        key = key as ECPrivateKey
        String d = EcJwkConverter.encodeCoordinate(key.params.curve.field.fieldSize, key.s)
        assertEquals jwk.d, d

        //remove the 'd' mapping to represent only a public key:
        jwk.remove('d')

        key = converter.toKey(jwk)
        assertTrue key instanceof ECPublicKey
        key = key as ECPublicKey
        String x = EcJwkConverter.encodeCoordinate(key.params.curve.field.fieldSize, key.w.affineX)
        String y = EcJwkConverter.encodeCoordinate(key.params.curve.field.fieldSize, key.w.affineY)
        assertEquals jwk.x, x
        assertEquals jwk.y, y
    }

    @Test
    @Ignore //TODO re-enable
    void testEcKeyPairToJwk() {

        KeyPair pair = SignatureAlgorithms.ES256.generateKeyPair()
        ECPublicKey pubKey = (ECPublicKey) pair.getPublic()

        DefaultJwkConverter converter = new DefaultJwkConverter()

        Map<String,String> jwk = converter.toJwk(pubKey)

        assertNotNull jwk
        assertEquals "EC", jwk.kty
        assertEquals Encoders.BASE64URL.encode(pubKey.w.affineX.toByteArray()), jwk.x
        assertEquals Encoders.BASE64URL.encode(pubKey.w.affineY.toByteArray()), jwk.y
        assertNull jwk.d //public keys should not populate the private key 'd' parameter
    }
}
