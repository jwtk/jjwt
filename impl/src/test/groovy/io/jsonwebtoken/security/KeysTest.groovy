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
//file:noinspection GrDeprecatedAPIUsage
package io.jsonwebtoken.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.DefaultJwtBuilder
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.security.*
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
                    "output size).  Consider using the Jwts.SIG.HS256.key() builder (or " +
                    "HS384.key() or HS512.key()) to create a key guaranteed to be secure enough " +
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
        for (SecureDigestAlgorithm alg : Jwts.SIG.get().values()) {
            if (alg instanceof MacAlgorithm) {
                SecretKey key = alg.key().build()
                assertEquals alg.getKeyBitLength(), Bytes.bitLength(key.getEncoded())
                assertEquals alg.jcaName, key.algorithm
                assertEquals alg, DefaultJwtBuilder.forSigningKey(key) // https://github.com/jwtk/jjwt/issues/381
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
                def keyAlgName = alg.jcaName.equals("RSASSA-PSS") ? "RSASSA-PSS" : alg.familyName
                assertEquals keyAlgName, pub.algorithm
                assertEquals alg.digestLength * 8, pub.modulus.bitLength()

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof RSAPrivateKey
                assertEquals keyAlgName, priv.algorithm
                assertEquals alg.digestLength * 8, priv.modulus.bitLength()

            } else if (alg.isEllipticCurve()) {

                KeyPair pair = Keys.keyPairFor(alg)
                assertNotNull pair

                int len = alg.minKeyLength
                String asn1oid = "secp${len}r1"
                String suffix = len == 256 ? ", X9.62 prime${len}v1" : ''
                //the JDK only adds this extra suffix to the secp256r1 curve name and not secp384r1 or secp521r1 curve names
                String jdkParamName = "$asn1oid [NIST P-${len}${suffix}]" as String

                PublicKey pub = pair.getPublic()
                assert pub instanceof ECPublicKey
                assertEquals "EC", pub.algorithm
                if (pub.params.hasProperty('name')) { // JDK <= 14
                    assertEquals jdkParamName, pub.params.name
                } else { // JDK >= 15
                    assertEquals asn1oid, pub.params.nameAndAliases[0]
                }
                assertEquals alg.minKeyLength, pub.params.order.bitLength()

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof ECPrivateKey
                assertEquals "EC", priv.algorithm
                if (priv.params.hasProperty('name')) { // JDK <= 14
                    assertEquals jdkParamName, priv.params.name
                } else { // JDK >= 15
                    assertEquals asn1oid, priv.params.nameAndAliases[0]
                }
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
    void testKeyPairBuilder() {

        Collection<SignatureAlgorithm> algs = Jwts.SIG.get().values()
                .findAll({ it instanceof KeyPairBuilderSupplier }) as Collection<SignatureAlgorithm>

        for (SignatureAlgorithm alg : algs) {

            String id = alg.getId()

            if (id.startsWith("RS") || id.startsWith("PS")) {

                def pair = alg.keyPair().build()
                assertNotNull pair

                PublicKey pub = pair.getPublic()
                assert pub instanceof RSAPublicKey
                assertEquals alg.preferredKeyBitLength, pub.modulus.bitLength()

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof RSAPrivateKey
                assertEquals alg.preferredKeyBitLength, priv.modulus.bitLength()

            } else if (id == "EdDSA") {

                def pair = alg.keyPair().build()
                assertNotNull pair

                PublicKey pub = pair.getPublic()
                assert pub instanceof PublicKey
                assertTrue EdwardsCurve.isEdwards(pub)

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof PrivateKey
                assertTrue EdwardsCurve.isEdwards(priv)

            } else if (id.startsWith("ES")) {

                def pair = alg.keyPair().build()
                assertNotNull pair

                int len = alg.orderBitLength
                String asn1oid = "secp${len}r1"
                String suffix = len == 256 ? ", X9.62 prime${len}v1" : ''
                //the JDK only adds this extra suffix to the secp256r1 curve name and not secp384r1 or secp521r1 curve names
                String jdkParamName = "$asn1oid [NIST P-${len}${suffix}]" as String

                PublicKey pub = pair.getPublic()
                assert pub instanceof ECPublicKey
                assertEquals "EC", pub.algorithm
                if (pub.params.hasProperty('name')) { // JDK <= 14
                    assertEquals jdkParamName, pub.params.name
                } else { // JDK >= 15
                    assertEquals asn1oid, pub.params.nameAndAliases[0]
                }
                assertEquals alg.orderBitLength, pub.params.order.bitLength()

                PrivateKey priv = pair.getPrivate()
                assert priv instanceof ECPrivateKey
                assertEquals "EC", priv.algorithm
                if (priv.params.hasProperty('name')) { // JDK <= 14
                    assertEquals jdkParamName, priv.params.name
                } else { // JDK >= 15
                    assertEquals asn1oid, priv.params.nameAndAliases[0]
                }
                assertEquals alg.orderBitLength, priv.params.order.bitLength()

            } else {
                // unexpected algorithm that is not accounted for in this test:
                fail()
            }
        }
    }

    @Test
    void testForPassword() {
        def password = "whatever".toCharArray()
        Password key = Keys.password(password)
        assertArrayEquals password, key.toCharArray()
        assertTrue key instanceof PasswordSpec
    }

    @Test
    void testAssociateWithECKey() {
        def priv = new TestPrivateKey(algorithm: 'EC')
        def pub = TestKeys.ES256.pair.public as ECPublicKey
        def result = Keys.builder(priv).publicKey(pub).build()
        assertTrue result instanceof PrivateECKey
        def key = result as PrivateECKey
        assertSame priv, key.getKey()
        assertSame pub.getParams(), key.getParams()
    }

    @Test
    void testAssociateWithKeyThatDoesntNeedToBeWrapped() {
        def pair = TestKeys.RS256.pair
        assertSame pair.private, Keys.builder(pair.private).publicKey(pair.public).build()
    }
}
