/*
 * Copyright © 2023 jsonwebtoken.io
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
import io.jsonwebtoken.security.InvalidKeyException
import org.junit.Test

import java.security.spec.PKCS8EncodedKeySpec

import static org.junit.Assert.*

class EdwardsCurveTest {

    static final Collection<EdwardsCurve> curves = EdwardsCurve.VALUES

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


    /**
     * Asserts bit lengths defined in:
     * - https://www.rfc-editor.org/rfc/rfc7748.html
     * - https://www.rfc-editor.org/rfc/rfc8032
     */
    @Test
    void testKeyBitLength() {
        assertEquals(255, EdwardsCurve.X25519.getKeyBitLength())
        assertEquals(255, EdwardsCurve.Ed25519.getKeyBitLength())
        assertEquals(448, EdwardsCurve.X448.getKeyBitLength())
        assertEquals(448, EdwardsCurve.Ed448.getKeyBitLength())
    }

    /**
     * Asserts encoding lengths defined in:
     * - https://www.rfc-editor.org/rfc/rfc7748.html
     * - https://www.rfc-editor.org/rfc/rfc8032
     */
    @Test
    void testEncodedKeyByteLength() {
        assertEquals 32, EdwardsCurve.X25519.encodedKeyByteLength
        assertEquals 32, EdwardsCurve.Ed25519.encodedKeyByteLength
        assertEquals 56, EdwardsCurve.X448.encodedKeyByteLength
        assertEquals 57, EdwardsCurve.Ed448.encodedKeyByteLength
    }

    @Test
    void testIsEdwardsNullKey() {
        assertFalse EdwardsCurve.isEdwards(null)
    }

    @Test
    void testForKeyNonEdwards() {
        def alg = 'foo'
        def key = new TestKey(algorithm: alg)
        try {
            EdwardsCurve.forKey(key)
        } catch (InvalidKeyException uke) {
            String msg = "Unrecognized Edwards Curve key: [${KeysBridge.toString(key)}]"
            assertEquals msg, uke.getMessage()
        }
    }

    @Test
    void testFindByKey() { // happy path test
        for (def alg : EdwardsCurve.VALUES) {
            def keyPair = alg.keyPair().build()
            def pub = keyPair.public
            def priv = keyPair.private
            assertSame alg, EdwardsCurve.findByKey(pub)
            assertSame alg, EdwardsCurve.findByKey(priv)
        }
    }

    @Test
    void testFindByNullKey() {
        assertNull EdwardsCurve.findByKey(null)
    }

    @Test
    void testFindByKeyUsingEncoding() {
        curves.each {
            def pair = TestKeys.forAlgorithm(it).pair
            def key = new TestKey(algorithm: 'foo', encoded: pair.public.getEncoded())
            def found = EdwardsCurve.findByKey(key)
            assertEquals(it, found)
        }
    }

    @Test
    void testFindByKeyUsingInvalidEncoding() {
        curves.each {
            byte[] encoded = new byte[it.encodedKeyByteLength]
            def key = new TestKey(algorithm: 'foo', encoded: encoded)
            assertNull EdwardsCurve.findByKey(key)
        }
    }

    @Test
    void testFindByKeyUsingMalformedEncoding() {
        curves.each {
            byte[] encoded = EdwardsCurve.ASN1_OID_PREFIX // just the prefix isn't enough
            def key = new TestKey(algorithm: 'foo', encoded: encoded)
            assertNull EdwardsCurve.findByKey(key)
        }
    }

    @Test
    void testFindByKeyWithValidCurveButExcessiveLength() {
        curves.each {
            byte[] badValue = Bytes.random(it.encodedKeyByteLength + 1) // invalid size, too large
            byte[] encoded = Bytes.concat(
                    EdwardsCurve.publicKeyAsn1Prefix(badValue.length, it.ASN1_OID),
                    badValue
            )
            def badKey = new TestPublicKey(encoded: encoded)
            assertNull EdwardsCurve.findByKey(badKey)
        }
    }

    @Test
    void testFindByKeyWithValidCurveButWeakLength() {
        curves.each {
            byte[] badValue = Bytes.random(it.encodedKeyByteLength - 1) // invalid size, too small
            byte[] encoded = Bytes.concat(
                    EdwardsCurve.publicKeyAsn1Prefix(badValue.length, it.ASN1_OID),
                    badValue
            )
            def badKey = new TestPublicKey(encoded: encoded)
            assertNull EdwardsCurve.findByKey(badKey)
        }
    }

    @Test
    void testToPrivateKey() {
        curves.each {
            def pair = TestKeys.forAlgorithm(it).pair
            def key = pair.getPrivate()
            def d = it.getKeyMaterial(key)
            def result = it.toPrivateKey(d, null)
            assertEquals(key, result)
        }
    }

    @Test
    void testToPublicKey() {
        curves.each {
            def bundle = TestKeys.forAlgorithm(it)
            def pair = bundle.pair
            def key = pair.getPublic()
            def x = it.getKeyMaterial(key)
            def result = it.toPublicKey(x, null)
            assertEquals(key, result)
        }
    }

    @Test
    void testToPrivateKeyInvalidLength() {
        curves.each {
            byte[] d = new byte[it.encodedKeyByteLength + 1] // more than required
            Randoms.secureRandom().nextBytes(d)
            try {
                it.toPrivateKey(d, null)
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.id} encoded PrivateKey length. Should be " +
                        "${Bytes.bytesMsg(it.encodedKeyByteLength)}, found ${Bytes.bytesMsg(d.length)}."
                assertEquals msg, ike.getMessage()
            }
        }
    }

    @Test
    void testPrivateKeySpecJdk11() {
        curves.each {
            byte[] d = new byte[it.encodedKeyByteLength]; Randoms.secureRandom().nextBytes(d)
            def keySpec = it.privateKeySpec(d, false) // standard = false for JDK 11 bug
            assertTrue keySpec instanceof PKCS8EncodedKeySpec
            def expectedEncoded = Bytes.concat(it.PRIVATE_KEY_JDK11_PREFIX, d)
            assertArrayEquals expectedEncoded, ((PKCS8EncodedKeySpec)keySpec).getEncoded()
        }
    }

    @Test
    void testToPublicKeyInvalidLength() {
        curves.each {
            byte[] x = new byte[it.encodedKeyByteLength - 1] // less than required
            Randoms.secureRandom().nextBytes(x)
            try {
                it.toPublicKey(x, null)
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.id} encoded PublicKey length. Should be " +
                        "${Bytes.bytesMsg(it.encodedKeyByteLength)}, found ${Bytes.bytesMsg(x.length)}."
                assertEquals msg, ike.getMessage()
            }
        }
    }

    /**
     * Ensures that if a DER NULL terminates the OID in the encoded key, the null tag is skipped.  This occurs in
     * some SunCE key encodings.
     */
    @Test
    void testGetKeyMaterialWithOidNullTerminator() {
        byte[] DER_NULL = [0x05, 0x00] as byte[]
        curves.each { it ->

            byte[] x = new byte[it.encodedKeyByteLength]
            Randoms.secureRandom().nextBytes(x)

            byte[] encoded = Bytes.concat(
                    [0x30, it.encodedKeyByteLength + 10 + DER_NULL.length, 0x30, 0x05] as byte[],
                    it.ASN1_OID,
                    DER_NULL, // this should be skipped when getting key material
                    [0x03, it.encodedKeyByteLength + 1, 0x00] as byte[],
                    x
            )

            def key = new TestKey(encoded: encoded)
            byte[] material = it.getKeyMaterial(key)
            assertArrayEquals(x, material)
        }
    }

    @Test
    void testGetKeyMaterialWithMissingEncodedBytes() {
        def key = new TestKey(algorithm: 'foo')
        curves.each {
            try {
                it.getKeyMaterial(key)
                fail()
            } catch (InvalidKeyException e) {
                String msg = "Missing required encoded bytes for key [${KeysBridge.toString(key)}]."
                assertEquals msg, e.getMessage()
            }
        }
    }

    @Test
    void testGetKeyMaterialInvalidKeyEncoding() {
        byte[] encoded = new byte[30]
        Randoms.secureRandom().nextBytes(encoded)
        //ensure random generator doesn't put in a byte that would cause other logic checks (0x03, 0x04, 0x05)
        encoded[0] = 0x20 // anything other than 0x03, 0x04, 0x05
        def key = new TestKey(encoded: encoded)
        curves.each {
            try {
                it.getKeyMaterial(key)
                fail()
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.getId()} ASN.1 encoding: Missing or incorrect algorithm OID." as String
                assertEquals msg, ike.getMessage()
            }
        }
    }

    @Test
    void testGetKeyMaterialInvalidKeyLength() {
        byte[] encoded = new byte[30]
        Randoms.secureRandom().nextBytes(encoded)
        //ensure random generator doesn't put in a byte that would cause other logic checks (0x03, 0x04, 0x05)
        encoded[0] = 0x20 // anything other than 0x03, 0x04, 0x05
        curves.each {
            // prefix it with the OID to make it look valid:
            encoded = Bytes.concat(it.ASN1_OID, encoded)
            def key = new TestKey(encoded: encoded)
            try {
                it.getKeyMaterial(key)
                fail()
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.getId()} ASN.1 encoding: Invalid key length." as String
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
                byte[] encoded = Bytes.concat(it.PUBLIC_KEY_ASN1_PREFIX, keyBytes)
                encoded[11] = 0x01 // should always be zero
                def key = new TestKey(encoded: encoded)
                it.getKeyMaterial(key)
                fail()
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.getId()} ASN.1 encoding: BIT STREAM should not indicate unused bytes." as String
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
                byte[] encoded = Bytes.concat(it.PRIVATE_KEY_ASN1_PREFIX, keyBytes)
                encoded[14] = 0x0F // should always be 0x04 (ASN.1 SEQUENCE tag)
                def key = new TestKey(encoded: encoded)
                it.getKeyMaterial(key)
                fail()
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.getId()} ASN.1 encoding: Invalid key length." as String
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
                byte[] encoded = Bytes.concat(it.PUBLIC_KEY_ASN1_PREFIX, keyBytes)
                encoded[10] = (byte) (size + 1) // ASN.1 size value (zero byte + key bytes)
                def key = new TestKey(encoded: encoded)
                it.getKeyMaterial(key)
                fail()
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.getId()} ASN.1 encoding: Invalid key length." as String
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
                byte[] encoded = Bytes.concat(it.PUBLIC_KEY_ASN1_PREFIX, keyBytes)
                encoded[10] = (byte) (size + 1) // ASN.1 size value (zero byte + key bytes)
                def key = new TestKey(encoded: encoded)
                it.getKeyMaterial(key)
                fail()
            } catch (InvalidKeyException ike) {
                String msg = "Invalid ${it.getId()} ASN.1 encoding: Invalid key length." as String
                assertEquals msg, ike.getMessage()
            }
        }
    }

    @Test
    void testDerivePublicKeyFromPrivateKey() {
        for (def curve : EdwardsCurve.VALUES) {
            def pair = curve.keyPair().build() // generate a standard key pair using the JCA APIs
            def pubKey = pair.getPublic()
            def derivedPubKey = EdwardsCurve.derivePublic(pair.getPrivate())
            // ensure our derived key matches the original JCA one:
            assertEquals(pubKey, derivedPubKey)
        }
    }
}
