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
import io.jsonwebtoken.impl.lang.Function
import io.jsonwebtoken.impl.lang.Functions
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.UnsupportedKeyException
import org.junit.Test

import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.KeySpec

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
        def key = new TestKey(algorithm: alg)
        try {
            EdwardsCurve.forKey(key)
        } catch (UnsupportedKeyException uke) {
            String msg = "${key.getClass().getName()} with algorithm '${alg}' is not a recognized Edwards Curve key."
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
                String msg = "Invalid ${it.id} encoded PrivateKey length. Should be " +
                        "${Bytes.bitsMsg(it.keyBitLength)}, found ${Bytes.bytesMsg(d.length)}."
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
                String msg = "Invalid ${it.id} encoded PublicKey length. Should be " +
                        "${Bytes.bitsMsg(it.keyBitLength)}, found ${Bytes.bytesMsg(x.length)}."
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
                    it.DER_OID,
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
            } catch (UnsupportedKeyException uke) {
                String msg = "${key.getClass().getName()} encoded bytes cannot be null or empty."
                assertEquals msg, uke.getMessage()
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
                String msg = "Invalid ${it.getId()} DER encoding: Missing or incorrect algorithm OID." as String
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
            encoded = Bytes.concat(it.DER_OID, encoded)
            def key = new TestKey(encoded: encoded)
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

    @Test
    void testParamKeySpecFactoryWithNullSpec() {
        def fn = EdwardsCurve.paramKeySpecFactory(null, true)
        assertSame Functions.forNull(), fn
    }

    @Test
    void testXecParamKeySpecFactory() {
        AlgorithmParameterSpec spec = new ECGenParameterSpec('foo') // any impl will do for this test
        def fn = EdwardsCurve.paramKeySpecFactory(spec, false) as EdwardsCurve.ParameterizedKeySpecFactory
        assertSame spec, fn.params
        assertSame EdwardsCurve.XEC_PRIV_KEY_SPEC_CTOR, fn.keySpecFactory
    }

    @Test
    void testEdEcParamKeySpecFactory() {
        AlgorithmParameterSpec spec = new ECGenParameterSpec('foo') // any impl will do for this test
        def fn = EdwardsCurve.paramKeySpecFactory(spec, true) as EdwardsCurve.ParameterizedKeySpecFactory
        assertSame spec, fn.params
        assertSame EdwardsCurve.EDEC_PRIV_KEY_SPEC_CTOR, fn.keySpecFactory
    }

    @Test
    void testParamKeySpecFactoryInvocation() {
        AlgorithmParameterSpec spec = new ECGenParameterSpec('foo') // any impl will do for this test
        KeySpec keySpec = new PasswordSpec("foo".toCharArray()) // any KeySpec impl will do

        byte[] d = new byte[32]
        Randoms.secureRandom().nextBytes(d)

        def keySpecFn = new Function<Object, KeySpec>() {
            @Override
            KeySpec apply(Object o) {
                assertTrue o instanceof Object[]
                Object[] args = (Object[]) o
                assertSame spec, args[0]
                assertSame d, args[1]
                return keySpec // simulate a creation
            }
        }

        def fn = new EdwardsCurve.ParameterizedKeySpecFactory(spec, keySpecFn)
        def result = fn.apply(d)
        assertSame keySpec, result
    }
}
