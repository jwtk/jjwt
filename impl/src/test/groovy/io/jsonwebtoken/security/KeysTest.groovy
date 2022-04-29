/*
 * Copyright (C) 2014 jsonwebtoken.io
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
package io.jsonwebtoken.security

import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.security.DefaultEllipticCurveSignatureAlgorithm
import io.jsonwebtoken.impl.security.DefaultPasswordKey
import io.jsonwebtoken.impl.security.DefaultRsaSignatureAlgorithm
import io.jsonwebtoken.impl.security.KeysBridge
import org.junit.Test

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.*

@SuppressWarnings('GroovyAccessibility')
class KeysTest {

    private static final Random RANDOM = new SecureRandom()

    static byte[] bytes(int sizeInBits) {
        byte[] bytes = new byte[sizeInBits / Byte.SIZE]
        RANDOM.nextBytes(bytes)
        return bytes
    }

    @Test
    void testPrivateCtor() { //for code coverage purposes only
        //noinspection GroovyResultOfObjectAllocationIgnored
        new Keys()
        new KeysBridge()
    }

    @Test
    void testHmacShaKeyForWithNullArgument() {
        try {
            Keys.hmacShaKeyFor(null)
        } catch (InvalidKeyException expected) {
            assertEquals 'SecretKey byte array cannot be null.', expected.message
        }
    }

    @Test
    void testHmacShaKeyForWithWeakKey() {
        int numBytes = 31
        int numBits = numBytes * 8
        try {
            Keys.hmacShaKeyFor(new byte[numBytes])
        } catch (WeakKeyException expected) {
            assertEquals "The specified key byte array is " + numBits + " bits which " +
                    "is not secure enough for any JWT HMAC-SHA algorithm.  The JWT " +
                    "JWA Specification (RFC 7518, Section 3.2) states that keys used with HMAC-SHA algorithms MUST have a " +
                    "size >= 256 bits (the key size must be greater than or equal to the hash " +
                    "output size).  Consider using the SignatureAlgorithms.HS256.generateKey() method (or " +
                    "HS384.generateKey() or HS512.generateKey()) to create a key guaranteed to be secure enough " +
                    "for your preferred HMAC-SHA algorithm.  See " +
                    "https://tools.ietf.org/html/rfc7518#section-3.2 for more information." as String, expected.message
        }
    }

    @Test
    void testHmacShaWithValidSizes() {
        for (int i : [256, 384, 512]) {
            byte[] bytes = bytes(i)
            def key = Keys.hmacShaKeyFor(bytes)
            assertTrue key instanceof SecretKeySpec
            assertEquals "HmacSHA$i" as String, key.getAlgorithm()
            assertTrue Arrays.equals(bytes, key.getEncoded())
        }
    }

    @Test
    void testHmacShaLargerThan512() {
        def key = Keys.hmacShaKeyFor(bytes(520))
        assertTrue key instanceof SecretKeySpec
        assertEquals 'HmacSHA512', key.getAlgorithm()
        assertTrue key.getEncoded().length * Byte.SIZE >= 512
    }

    @Test
    @Deprecated
    void testDeprecatedSecretKeyFor() {

        for (io.jsonwebtoken.SignatureAlgorithm alg : io.jsonwebtoken.SignatureAlgorithm.values()) {

            String name = alg.name()

            if (alg.isHmac()) {
                SecretKey key = Keys.secretKeyFor(alg)
                assertEquals alg.minKeyLength, key.getEncoded().length * 8 //convert byte count to bit count
                assertEquals alg.jcaName, key.algorithm
                alg.assertValidSigningKey(key)
                alg.assertValidVerificationKey(key)
                assertEquals alg, io.jsonwebtoken.SignatureAlgorithm.forSigningKey(key)
                // https://github.com/jwtk/jjwt/issues/381
            } else {
                try {
                    Keys.secretKeyFor(alg)
                    fail()
                } catch (IllegalArgumentException expected) {
                    assertEquals "The $name algorithm does not support shared secret keys." as String, expected.message
                }

            }
        }
    }

    @Test
    void testSecretKeyFor() {
        for (SignatureAlgorithm alg : SignatureAlgorithms.values()) {
            if (alg instanceof SecretKeySignatureAlgorithm) {
                SecretKey key = alg.keyBuilder().build()
                assertEquals alg.getKeyBitLength(), Bytes.bitLength(key.getEncoded())
                assertEquals alg.jcaName, key.algorithm
                assertEquals alg, SignatureAlgorithms.forSigningKey(key) // https://github.com/jwtk/jjwt/issues/381
            }
        }
    }

    @Test
    @Deprecated
    void testDeprecatedKeyPairFor() {

        for (io.jsonwebtoken.SignatureAlgorithm alg : io.jsonwebtoken.SignatureAlgorithm.values()) {

            String name = alg.name()

            if (alg.isRsa()) {

                KeyPair pair = Keys.keyPairFor(alg)
                assertNotNull pair

                PublicKey pub = pair.getPublic()
                assert pub instanceof RSAPublicKey
                assertEquals alg.familyName, pub.algorithm
                assertEquals alg.digestLength * 8, pub.modulus.bitLength()

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof RSAPrivateKey
                assertEquals alg.familyName, priv.algorithm
                assertEquals alg.digestLength * 8, priv.modulus.bitLength()

            } else if (alg.isEllipticCurve()) {

                KeyPair pair = Keys.keyPairFor(alg);
                assertNotNull pair

                int len = alg.minKeyLength
                String asn1oid = "secp${len}r1"
                String suffix = len == 256 ? ", X9.62 prime${len}v1" : ''
                //the JDK only adds this extra suffix to the secp256r1 curve name and not secp384r1 or secp521r1 curve names
                String jdkParamName = "$asn1oid [NIST P-${len}${suffix}]" as String

                PublicKey pub = pair.getPublic()
                assert pub instanceof ECPublicKey
                assertEquals "EC", pub.algorithm
                assertEquals jdkParamName, pub.params.name
                assertEquals alg.minKeyLength, pub.params.order.bitLength()

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof ECPrivateKey
                assertEquals "EC", priv.algorithm
                assertEquals jdkParamName, priv.params.name
                assertEquals alg.minKeyLength, priv.params.order.bitLength()

            } else {
                try {
                    Keys.keyPairFor(alg)
                    fail()
                } catch (IllegalArgumentException expected) {
                    assertEquals "The $name algorithm does not support Key Pairs." as String, expected.message
                }
            }
        }
    }

    @Test
    void testKeyPairFor() {

        for (SignatureAlgorithm alg : SignatureAlgorithms.values()) {

            if (alg instanceof DefaultRsaSignatureAlgorithm) {

                KeyPair pair = alg.generateKeyPair()
                assertNotNull pair

                PublicKey pub = pair.getPublic()
                assert pub instanceof RSAPublicKey
                assertEquals alg.preferredKeyLength, pub.modulus.bitLength()

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof RSAPrivateKey
                assertEquals alg.preferredKeyLength, priv.modulus.bitLength()

            } else if (alg instanceof DefaultEllipticCurveSignatureAlgorithm) {

                KeyPair pair = alg.generateKeyPair()
                assertNotNull pair

                int len = alg.orderBitLength
                String asn1oid = "secp${len}r1"
                String suffix = len == 256 ? ", X9.62 prime${len}v1" : ''
                //the JDK only adds this extra suffix to the secp256r1 curve name and not secp384r1 or secp521r1 curve names
                String jdkParamName = "$asn1oid [NIST P-${len}${suffix}]" as String

                PublicKey pub = pair.getPublic()
                assert pub instanceof ECPublicKey
                assertEquals "EC", pub.algorithm
                assertEquals jdkParamName, pub.params.name
                assertEquals alg.orderBitLength, pub.params.order.bitLength()

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof ECPrivateKey
                assertEquals "EC", priv.algorithm
                assertEquals jdkParamName, priv.params.name
                assertEquals alg.orderBitLength, priv.params.order.bitLength()

            } else {
                assertFalse alg instanceof AsymmetricKeySignatureAlgorithm
                //assert we've accounted for all asymmetric ones above
            }
        }
    }

    @Test
    void testForPassword() {
        def password = "whatever".toCharArray()
        PasswordKey key = Keys.forPassword(password)
        assertArrayEquals password, key.getPassword()
        assertTrue key instanceof DefaultPasswordKey
    }
}
