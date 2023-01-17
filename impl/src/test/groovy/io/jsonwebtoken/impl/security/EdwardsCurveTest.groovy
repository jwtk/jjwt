package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.UnsupportedKeyException
import org.junit.Test

import static org.junit.Assert.*

class EdwardsCurveTest {

    static final def curves = EdwardsCurve.VALUES

    @SuppressWarnings('GroovyResultOfObjectAllocationIgnored')
    @Test
    void testInvalidOidTerminalNode() {
        try {
            new EdwardsCurve('foo', 200)
            fail()
        } catch (IllegalArgumentException iae) {
            String expected = 'Invalid Edwards Curve ASN.1 OID terminal node value'
            assertEquals expected, iae.getMessage()
        }
    }

    @Test
    void testKeyBitLength() {
        assertEquals(256, EdwardsCurve.X25519.getKeyBitLength())
        assertEquals(256, EdwardsCurve.Ed25519.getKeyBitLength())
        assertEquals(448, EdwardsCurve.X448.getKeyBitLength())
        assertEquals(456, EdwardsCurve.Ed448.getKeyBitLength())
    }

    @Test
    void testIsEdwardsNullKey() {
        assertFalse EdwardsCurve.isEdwards(null)
    }

    @Test
    void testFindByNullKey() {
        assertNull EdwardsCurve.findByKey(null)
    }

    @Test
    void testForKeyNonEdwards() {
        def alg = 'foo'
        try {
            EdwardsCurve.forKey(new TestKey(algorithm: alg))
        } catch (UnsupportedKeyException uke) {
            String msg = "TestKey with algorithm '${alg}' is not a recognized Edwards Curve key."
            assertEquals msg, uke.getMessage()
        }
    }

    @Test
    void testFindByKeyUsingEncoding() {
        curves.each {
            def pair = TestKeys.forCurve(it).pair
            def key = new TestKey(algorithm: 'foo', encoded: pair.public.getEncoded())
            def found = EdwardsCurve.findByKey(key)
            assertEquals(it, found)
        }
    }

    @Test
    void testFindByKeyUsingInvalidEncoding() {
        curves.each {
            byte[] encoded = new byte[it.keyBitLength / 8]
            def key = new TestKey(algorithm: 'foo', encoded: encoded)
            assertNull EdwardsCurve.findByKey(key)
        }
    }

    @Test
    void testFindByKeyUsingMalformedEncoding() {
        curves.each {
            byte[] encoded = EdwardsCurve.DER_OID_PREFIX // just the prefix isn't enough
            def key = new TestKey(algorithm: 'foo', encoded: encoded)
            assertNull EdwardsCurve.findByKey(key)
        }
    }

    @Test
    void testToPrivateKey() {
        curves.each {
            def pair = TestKeys.forCurve(it).pair
            def key = pair.getPrivate()
            def d = it.getKeyMaterial(key)
            def result = it.toPrivateKey(d, it.getProvider())
            assertEquals(key, result)
        }
    }

    @Test
    void testToPublicKey() {
        curves.each {
            def pair = TestKeys.forCurve(it).pair
            def key = pair.getPublic()
            def x = it.getKeyMaterial(key)
            def result = it.toPublicKey(x, it.getProvider())
            assertEquals(key, result)
        }
    }

    @Test
    void testToPrivateKeyInvalidLength() {
        curves.each {
            byte[] d = new byte[it.encodedKeyByteLength + 1] // more than required
            Randoms.secureRandom().nextBytes(d)
            try {
                it.toPrivateKey(d, it.getProvider())
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.id} encoded key length. Should be ${Bytes.bitsMsg(it.keyBitLength)}, " +
                        "found ${Bytes.bytesMsg(d.length)}."
                assertEquals msg, ike.getMessage()
            }
        }
    }

    @Test
    void testToPublicKeyInvalidLength() {
        curves.each {
            byte[] x = new byte[it.encodedKeyByteLength - 1] // less than required
            Randoms.secureRandom().nextBytes(x)
            try {
                it.toPublicKey(x, it.getProvider())
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.id} encoded key length. Should be ${Bytes.bitsMsg(it.keyBitLength)}, " +
                        "found ${Bytes.bytesMsg(x.length)}."
                assertEquals msg, ike.getMessage()
            }
        }
    }

    @Test
    void testGetKeyMaterialWithMissingEncodedBytes() {
        def key = new TestKey(algorithm: 'foo')
        curves.each {
            try {
                it.getKeyMaterial(key)
                fail()
            } catch (UnsupportedKeyException uke) {
                String msg = "TestKey encoded bytes cannot be null or empty."
                assertEquals msg, uke.getMessage()
            }
        }
    }

    @Test
    void testGetKeyMaterialInvalidKeyEncoding() {
        byte[] fake = new byte[30]
        Randoms.secureRandom().nextBytes(fake)
        def key = new TestKey(encoded: fake)
        curves.each {
            try {
                it.getKeyMaterial(key)
                fail()
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.getId()} DER encoding: Invalid key length." as String
                assertEquals msg, ike.getMessage()
            }
        }
    }

    @Test
    void testPublicKeyMaterialInvalidBitSequence() {
        int size = 0
        curves.each {
            try {
                size = it.encodedKeyByteLength
                byte[] keyBytes = new byte[size]
                Randoms.secureRandom().nextBytes(keyBytes)
                byte[] encoded = Bytes.concat(it.PUBLIC_KEY_DER_PREFIX, keyBytes)
                encoded[11] = 0x01 // should always be zero
                def key = new TestKey(encoded: encoded)
                it.getKeyMaterial(key)
                fail()
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.getId()} DER encoding: BIT STREAM should not indicate unused bytes." as String
                assertEquals msg, ike.getMessage()
            }
        }
    }

    @Test
    void testPrivateKeyMaterialInvalidOctetSequence() {
        int size = 0
        curves.each {
            try {
                size = it.encodedKeyByteLength
                byte[] keyBytes = new byte[size]
                Randoms.secureRandom().nextBytes(keyBytes)
                byte[] encoded = Bytes.concat(it.PRIVATE_KEY_DER_PREFIX, keyBytes)
                encoded[14] = 0x0F // should always be 0x04 (DER SEQUENCE tag)
                def key = new TestKey(encoded: encoded)
                it.getKeyMaterial(key)
                fail()
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.getId()} DER encoding: Invalid key length." as String
                assertEquals msg, ike.getMessage()
            }
        }
    }

    @Test
    void testGetKeyMaterialTooShort() {
        int size = 0
        curves.each {
            try {
                size = it.encodedKeyByteLength - 1 // one less than required
                byte[] keyBytes = new byte[size]
                Randoms.secureRandom().nextBytes(keyBytes)
                byte[] encoded = Bytes.concat(it.PUBLIC_KEY_DER_PREFIX, keyBytes)
                encoded[10] = (byte) (size + 1) // DER size value (zero byte + key bytes)
                def key = new TestKey(encoded: encoded)
                it.getKeyMaterial(key)
                fail()
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.getId()} DER encoding: Invalid key length." as String
                assertEquals msg, ike.getMessage()
            }
        }
    }

    @Test
    void testGetKeyMaterialTooLong() {
        int size = 0
        curves.each {
            try {
                size = it.encodedKeyByteLength + 1 // one less than required
                byte[] keyBytes = new byte[size]
                Randoms.secureRandom().nextBytes(keyBytes)
                byte[] encoded = Bytes.concat(it.PUBLIC_KEY_DER_PREFIX, keyBytes)
                encoded[10] = (byte) (size + 1) // DER size value (zero byte + key bytes)
                def key = new TestKey(encoded: encoded)
                it.getKeyMaterial(key)
                fail()
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.getId()} DER encoding: Invalid key length." as String
                assertEquals msg, ike.getMessage()
            }
        }
    }
}
