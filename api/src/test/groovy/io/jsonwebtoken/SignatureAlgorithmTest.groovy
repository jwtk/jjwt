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
package io.jsonwebtoken

import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SignatureException
import io.jsonwebtoken.security.WeakKeyException
import org.junit.Test

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.security.Key
import java.security.PrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECParameterSpec

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class SignatureAlgorithmTest {

    @Test
    void testNames() {
        def algNames = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512',
                        'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'NONE']

        for (String name : algNames) {
            testName(name)
        }
    }

    private static void testName(String name) {
        def alg = SignatureAlgorithm.forName(name);
        def namedAlg = name as SignatureAlgorithm //Groovy type coercion FTW!
        assertTrue alg == namedAlg
        assert alg.description != null && alg.description != ""
    }

    @Test(expected = SignatureException)
    void testUnrecognizedAlgorithmName() {
        SignatureAlgorithm.forName('whatever')
    }

    @Test
    void testIsHmac() {
        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {
            if (alg.name().startsWith("HS")) {
                assertTrue alg.isHmac()
            } else {
                assertFalse alg.isHmac()
            }
        }
    }

    @Test
    void testHmacFamilyName() {
        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {
            if (alg.name().startsWith("HS")) {
                assertEquals alg.getFamilyName(), "HMAC"
            }
        }
    }

    @Test
    void testIsRsa() {
        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {
            if (alg.getDescription().startsWith("RSASSA")) {
                assertTrue alg.isRsa()
            } else {
                assertFalse alg.isRsa()
            }
        }
    }

    @Test
    void testRsaFamilyName() {
        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {
            if (alg.name().startsWith("RS") || alg.name().startsWith("PS")) {
                assertEquals alg.getFamilyName(), "RSA"
            }
        }
    }

    @Test
    void testIsEllipticCurve() {
        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {
            if (alg.name().startsWith("ES")) {
                assertTrue alg.isEllipticCurve()
            } else {
                assertFalse alg.isEllipticCurve()
            }
        }
    }

    @Test
    void testEllipticCurveFamilyName() {
        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {
            if (alg.name().startsWith("ES")) {
                assertEquals alg.getFamilyName(), "ECDSA"
            }
        }
    }

    @Test
    void testIsJdkStandard() {
        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {
            if (alg.name().startsWith("PS") || alg == SignatureAlgorithm.NONE) {
                assertFalse alg.isJdkStandard()
            } else {
                assertTrue alg.isJdkStandard()
            }
        }
    }

    @Test
    void testGetMinKeyLength() {
        for(SignatureAlgorithm alg : SignatureAlgorithm.values()) {
            if (alg == SignatureAlgorithm.NONE) {
                assertEquals 0, alg.getMinKeyLength()
            } else {
                if (alg.isRsa()) {
                    assertEquals 2048, alg.getMinKeyLength()
                } else {
                    int num = alg.name().substring(2, 5).toInteger()
                    if (alg == SignatureAlgorithm.ES512) {
                        num = 521
                    }
                    assertEquals num, alg.getMinKeyLength()
                }
            }
        }
    }

    @Test
    void testForSigningKeyNullArgument() {
        try {
            SignatureAlgorithm.forSigningKey(null)
        } catch (InvalidKeyException expected) {
            assertEquals 'Key argument cannot be null.', expected.message
        }
    }

    @Test
    void testForSigningKeyInvalidType() {
        def key = new Key() {
            @Override
            String getAlgorithm() {
                return null
            }

            @Override
            String getFormat() {
                return null
            }

            @Override
            byte[] getEncoded() {
                return new byte[0]
            }
        }

        try {
            SignatureAlgorithm.forSigningKey(key)
            fail()
        } catch (InvalidKeyException expected) {
            assertTrue expected.getMessage().startsWith("JWT standard signing algorithms require either 1) a " +
                    "SecretKey for HMAC-SHA algorithms or 2) a private RSAKey for RSA algorithms or 3) a private " +
                    "ECKey for Elliptic Curve algorithms.  The specified key is of type ")
        }
    }

    @Test
    void testForSigningKeySecretKeyWeakKey() {
        try {
            SignatureAlgorithm.forSigningKey(new SecretKeySpec(new byte[1], 'HmacSHA256'))
            fail()
        } catch (WeakKeyException expected) {
        }
    }

    @Test
    void testForSigningKeySecretKeyHappyPath() {
        for(SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {
            int numBytes = alg.minKeyLength / 8 as int
            assertEquals alg, SignatureAlgorithm.forSigningKey(Keys.hmacShaKeyFor(new byte[numBytes]))
        }
    }

    @Test
    void testForSigningKeyRSAWeakKey() {

        RSAPrivateKey key = createMock(RSAPrivateKey)
        BigInteger modulus = createMock(BigInteger)
        expect(key.getModulus()).andStubReturn(modulus)
        expect(modulus.bitLength()).andStubReturn(1024)

        replay key, modulus

        try {
            SignatureAlgorithm.forSigningKey(key)
            fail()
        } catch (WeakKeyException expected) {
        }

        verify key, modulus
    }

    @Test
    void testForSigningKeyRSAHappyPath() {

        for(SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.name().startsWith("RS") }) {

            int heuristicKeyLength = (alg == SignatureAlgorithm.RS512 ? 4096 : (alg == SignatureAlgorithm.RS384 ? 3072 : 2048))

            RSAPrivateKey key = createMock(RSAPrivateKey)
            BigInteger modulus = createMock(BigInteger)
            expect(key.getModulus()).andStubReturn(modulus)
            expect(modulus.bitLength()).andStubReturn(heuristicKeyLength)

            replay key, modulus

            assertEquals alg, SignatureAlgorithm.forSigningKey(key)

            verify key, modulus
        }
    }

    @Test
    void testForSigningKeyECWeakKey() {

        ECPrivateKey key = createMock(ECPrivateKey)
        ECParameterSpec spec = createMock(ECParameterSpec)
        BigInteger order = createMock(BigInteger)
        expect(key.getParams()).andStubReturn(spec)
        expect(spec.getOrder()).andStubReturn(order)
        expect(order.bitLength()).andReturn(128)

        replay key, spec, order

        try {
            SignatureAlgorithm.forSigningKey(key)
            fail()
        } catch (WeakKeyException expected) {
        }

        verify key, spec, order
    }

    @Test
    void testForSigningKeyECHappyPath() {

        for(SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isEllipticCurve() }) {

            ECPrivateKey key = createMock(ECPrivateKey)
            ECParameterSpec spec = createMock(ECParameterSpec)
            BigInteger order = createMock(BigInteger)
            expect(key.getParams()).andStubReturn(spec)
            expect(spec.getOrder()).andStubReturn(order)
            expect(order.bitLength()).andStubReturn(alg.minKeyLength)

            replay key, spec, order

            assertEquals alg, SignatureAlgorithm.forSigningKey(key)

            verify key, spec, order
        }
    }

    @Test
    void testAssertValidSigningKeyWithNoneAlgorithm() {
        Key key = createMock(Key)
        try {
            SignatureAlgorithm.NONE.assertValidSigningKey(key)
            fail()
        } catch (InvalidKeyException expected) {
            assertEquals "The 'NONE' signature algorithm does not support cryptographic keys." as String, expected.message
        }
    }

    @Test
    void testAssertValidHmacSigningKeyHappyPath() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {

            SecretKey key = createMock(SecretKey)
            int numBits = alg.minKeyLength
            int numBytes = numBits / 8 as int
            expect(key.getEncoded()).andReturn(new byte[numBytes])
            expect(key.getAlgorithm()).andReturn(alg.jcaName)

            replay key

            alg.assertValidSigningKey(key)

            verify key
        }
    }

    @Test
    void testAssertValidHmacSigningKeyNotSecretKey() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {

            Key key = createMock(Key)

            try {
                alg.assertValidSigningKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals 'HMAC signing keys must be SecretKey instances.', expected.message
            }
        }
    }

    @Test
    void testAssertValidHmacSigningKeyNullBytes() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {

            SecretKey key = createMock(SecretKey)
            expect(key.getEncoded()).andReturn(null)

            replay key

            try {
                alg.assertValidSigningKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals "The signing key's encoded bytes cannot be null.", expected.message
            }

            verify key
        }
    }

    @Test
    void testAssertValidHmacSigningKeyMissingAlgorithm() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {

            SecretKey key = createMock(SecretKey)
            expect(key.getEncoded()).andReturn(new byte[alg.minKeyLength / 8 as int])
            expect(key.getAlgorithm()).andReturn(null)

            replay key

            try {
                alg.assertValidSigningKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals "The signing key's algorithm cannot be null.", expected.message
            }

            verify key
        }
    }

    @Test // https://github.com/jwtk/jjwt/issues/381
    void testAssertValidHmacSigningKeyCaseInsensitiveJcaName() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {

            SecretKey key = createMock(SecretKey)
            int numBits = alg.minKeyLength
            int numBytes = numBits / 8 as int
            expect(key.getEncoded()).andReturn(new byte[numBytes])
            expect(key.getAlgorithm()).andReturn(alg.jcaName.toUpperCase()) // <-- upper case, non standard JCA name

            replay key

            alg.assertValidSigningKey(key)

            verify key
        }
    }

    @Test
    void testAssertValidHmacSigningKeyUnsupportedAlgorithm() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {

            SecretKey key = createMock(SecretKey)
            expect(key.getEncoded()).andReturn(new byte[alg.minKeyLength / 8 as int])
            expect(key.getAlgorithm()).andReturn('AES')

            replay key

            try {
                alg.assertValidSigningKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals "The signing key's algorithm 'AES' does not equal a valid HmacSHA* algorithm " +
                        "name and cannot be used with ${alg.name()}." as String, expected.message
            }

            verify key
        }
    }

    @Test
    void testAssertValidHmacSigningKeyInsufficientKeyLength() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {

            SecretKey key = createMock(SecretKey)
            int numBits = alg.minKeyLength - 8 //8 bits shorter than expected
            int numBytes = numBits / 8 as int
            expect(key.getEncoded()).andReturn(new byte[numBytes])
            expect(key.getAlgorithm()).andReturn(alg.jcaName)

            replay key

            try {
                alg.assertValidSigningKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals "The signing key's size is $numBits bits which is not secure enough for the " +
                        "${alg.name()} algorithm.  The JWT JWA Specification " +
                        "(RFC 7518, Section 3.2) states that keys used with ${alg.name()} MUST have a size >= " +
                        "${alg.minKeyLength} bits (the key size must be greater than or equal to the hash output " +
                        "size).  Consider using the ${Keys.class.getName()} class's 'secretKeyFor(" +
                        "SignatureAlgorithm.${alg.name()})' method to create a key guaranteed to be secure enough " +
                        "for ${alg.name()}.  See https://tools.ietf.org/html/rfc7518#section-3.2 for " +
                        "more information." as String, expected.message
            }

            verify key
        }
    }

    @Test
    void testAssertValidECSigningKeyHappyPath() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isEllipticCurve() }) {

            ECPrivateKey key = createMock(ECPrivateKey)
            ECParameterSpec spec = createMock(ECParameterSpec)
            BigInteger order = createMock(BigInteger)
            expect(key.getParams()).andStubReturn(spec)
            expect(spec.getOrder()).andStubReturn(order)
            expect(order.bitLength()).andStubReturn(alg.minKeyLength)

            replay key, spec, order

            alg.assertValidSigningKey(key)

            verify key, spec, order
        }
    }

    @Test
    void testAssertValidECSigningNotPrivateKey() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isEllipticCurve() }) {

            ECPublicKey key = createMock(ECPublicKey)

            replay key

            try {
                alg.assertValidSigningKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals 'ECDSA signing keys must be PrivateKey instances.', expected.message
            }

            verify key
        }
    }

    @Test
    void testAssertValidECSigningKeyNotECKey() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isEllipticCurve() }) {

            PrivateKey key = createMock(PrivateKey)

            try {
                alg.assertValidSigningKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals 'ECDSA signing keys must be ECKey instances.', expected.message
            }
        }
    }

    @Test
    void testAssertValidECSigningKeyInsufficientKeyLength() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isEllipticCurve() }) {

            ECPrivateKey key = createMock(ECPrivateKey)
            ECParameterSpec spec = createMock(ECParameterSpec)
            BigInteger order = createMock(BigInteger)
            expect(key.getParams()).andStubReturn(spec)
            expect(spec.getOrder()).andStubReturn(order)
            expect(order.bitLength()).andStubReturn(alg.minKeyLength - 8) //1 byte less than expected

            replay key, spec, order

            try {
                alg.assertValidSigningKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals "The signing key's size (ECParameterSpec order) is ${order.bitLength()} bits " +
                        "which is not secure enough for the ${alg.name()} algorithm.  The JWT JWA Specification " +
                        "(RFC 7518, Section 3.4) states that keys used with ${alg.name()} MUST have a size >= " +
                        "${alg.minKeyLength} bits.  Consider using the ${Keys.class.getName()} class's " +
                        "'keyPairFor(SignatureAlgorithm.${alg.name()})' method to create a key pair guaranteed " +
                        "to be secure enough for ${alg.name()}.  See " +
                        "https://tools.ietf.org/html/rfc7518#section-3.4 for more information." as String, expected.message
            }

            verify key, spec, order
        }
    }

    @Test
    void testAssertValidRSASigningKeyHappyPath() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isRsa() }) {

            RSAPrivateKey key = createMock(RSAPrivateKey)
            BigInteger modulus = createMock(BigInteger)
            expect(key.getModulus()).andStubReturn(modulus)
            expect(modulus.bitLength()).andStubReturn(alg.minKeyLength)

            replay key, modulus

            alg.assertValidSigningKey(key)

            verify key, modulus
        }
    }

    @Test
    void testAssertValidRSASigningNotPrivateKey() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isRsa() }) {

            RSAPublicKey key = createMock(RSAPublicKey)

            replay key

            try {
                alg.assertValidSigningKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals 'RSA signing keys must be PrivateKey instances.', expected.message
            }

            verify key
        }
    }

    @Test
    void testAssertValidRSASigningKeyNotRSAKey() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isRsa() }) {

            PrivateKey key = createMock(PrivateKey)

            try {
                alg.assertValidSigningKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals 'RSA signing keys must be RSAKey instances.', expected.message
            }
        }
    }

    @Test
    void testAssertValidRSASigningKeyInsufficientKeyLength() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isRsa() }) {

            String section = alg.name().startsWith("P") ? "3.5" : "3.3"

            RSAPrivateKey key = createMock(RSAPrivateKey)
            BigInteger modulus = createMock(BigInteger)
            expect(key.getModulus()).andStubReturn(modulus)
            expect(modulus.bitLength()).andStubReturn(alg.minKeyLength - 8) // 1 less byte

            replay key, modulus

            try {
                alg.assertValidSigningKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals "The signing key's size is ${modulus.bitLength()} bits which is not secure " +
                        "enough for the ${alg.name()} algorithm.  The JWT JWA Specification " +
                        "(RFC 7518, Section ${section}) states that keys used with ${alg.name()} MUST have a size >= " +
                        "${alg.minKeyLength} bits.  Consider using the ${Keys.class.getName()} class's " +
                        "'keyPairFor(SignatureAlgorithm.${alg.name()})' method to create a key pair guaranteed " +
                        "to be secure enough for ${alg.name()}.  See " +
                        "https://tools.ietf.org/html/rfc7518#section-${section} for more information." as String, expected.message
            }

            verify key, modulus
        }
    }

    @Test
    void testAssertValidVerificationKeyWithNoneAlgorithm() {
        Key key = createMock(Key)
        try {
            SignatureAlgorithm.NONE.assertValidVerificationKey(key)
            fail()
        } catch (InvalidKeyException expected) {
            assertEquals "The 'NONE' signature algorithm does not support cryptographic keys." as String, expected.message
        }
    }

    @Test
    void testAssertValidHmacVerificationKeyHappyPath() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {

            SecretKey key = createMock(SecretKey)
            int numBits = alg.minKeyLength
            int numBytes = numBits / 8 as int
            expect(key.getEncoded()).andReturn(new byte[numBytes])
            expect(key.getAlgorithm()).andReturn(alg.jcaName)

            replay key

            alg.assertValidVerificationKey(key)

            verify key
        }
    }

    @Test
    void testAssertValidHmacVerificationKeyNotSecretKey() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {

            Key key = createMock(Key)

            try {
                alg.assertValidVerificationKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals 'HMAC verification keys must be SecretKey instances.', expected.message
            }
        }
    }

    @Test
    void testAssertValidHmacVerificationKeyNullBytes() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {

            SecretKey key = createMock(SecretKey)
            expect(key.getEncoded()).andReturn(null)

            replay key

            try {
                alg.assertValidVerificationKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals "The verification key's encoded bytes cannot be null.", expected.message
            }

            verify key
        }
    }

    @Test
    void testAssertValidHmacVerificationKeyMissingAlgorithm() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {

            SecretKey key = createMock(SecretKey)
            expect(key.getEncoded()).andReturn(new byte[alg.minKeyLength / 8 as int])
            expect(key.getAlgorithm()).andReturn(null)

            replay key

            try {
                alg.assertValidVerificationKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals "The verification key's algorithm cannot be null.", expected.message
            }

            verify key
        }
    }

    @Test
    void testAssertValidHmacVerificationKeyUnsupportedAlgorithm() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {

            SecretKey key = createMock(SecretKey)
            expect(key.getEncoded()).andReturn(new byte[alg.minKeyLength / 8 as int])
            expect(key.getAlgorithm()).andReturn('AES')

            replay key

            try {
                alg.assertValidVerificationKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals "The verification key's algorithm 'AES' does not equal a valid HmacSHA* algorithm " +
                        "name and cannot be used with ${alg.name()}." as String, expected.message
            }

            verify key
        }
    }

    @Test
    void testAssertValidHmacVerificationKeyInsufficientKeyLength() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isHmac() }) {

            SecretKey key = createMock(SecretKey)
            int numBits = alg.minKeyLength - 8 // 8 bits (1 byte) less than required
            int numBytes = numBits / 8 as int
            expect(key.getEncoded()).andReturn(new byte[numBytes])
            expect(key.getAlgorithm()).andReturn(alg.jcaName)

            replay key

            try {
                alg.assertValidVerificationKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals "The verification key's size is $numBits bits which is not secure enough for the " +
                        "${alg.name()} algorithm.  The JWT JWA Specification " +
                        "(RFC 7518, Section 3.2) states that keys used with ${alg.name()} MUST have a size >= " +
                        "${alg.minKeyLength} bits (the key size must be greater than or equal to the hash output " +
                        "size).  Consider using the ${Keys.class.getName()} class's 'secretKeyFor(" +
                        "SignatureAlgorithm.${alg.name()})' method to create a key guaranteed to be secure enough " +
                        "for ${alg.name()}.  See https://tools.ietf.org/html/rfc7518#section-3.2 for " +
                        "more information." as String, expected.message
            }

            verify key
        }
    }

    @Test
    void testAssertValidECVerificationKeyHappyPath() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isEllipticCurve() }) {

            ECPrivateKey key = createMock(ECPrivateKey)
            ECParameterSpec spec = createMock(ECParameterSpec)
            BigInteger order = createMock(BigInteger)
            expect(key.getParams()).andStubReturn(spec)
            expect(spec.getOrder()).andStubReturn(order)
            expect(order.bitLength()).andStubReturn(alg.minKeyLength)

            replay key, spec, order

            alg.assertValidVerificationKey(key)

            verify key, spec, order
        }
    }

    @Test
    void testAssertValidECVerificationKeyNotECKey() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isEllipticCurve() }) {

            PrivateKey key = createMock(PrivateKey)

            try {
                alg.assertValidVerificationKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals 'ECDSA verification keys must be ECKey instances.', expected.message
            }
        }
    }

    @Test
    void testAssertValidECVerificationKeyInsufficientKeyLength() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isEllipticCurve() }) {

            ECPrivateKey key = createMock(ECPrivateKey)
            ECParameterSpec spec = createMock(ECParameterSpec)
            BigInteger order = createMock(BigInteger)
            expect(key.getParams()).andStubReturn(spec)
            expect(spec.getOrder()).andStubReturn(order)
            expect(order.bitLength()).andStubReturn(alg.minKeyLength - 8) // 1 less byte

            replay key, spec, order

            try {
                alg.assertValidVerificationKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals "The verification key's size (ECParameterSpec order) is ${order.bitLength()} bits " +
                        "which is not secure enough for the ${alg.name()} algorithm.  The JWT JWA Specification " +
                        "(RFC 7518, Section 3.4) states that keys used with ${alg.name()} MUST have a size >= " +
                        "${alg.minKeyLength} bits.  Consider using the ${Keys.class.getName()} class's " +
                        "'keyPairFor(SignatureAlgorithm.${alg.name()})' method to create a key pair guaranteed " +
                        "to be secure enough for ${alg.name()}.  See " +
                        "https://tools.ietf.org/html/rfc7518#section-3.4 for more information." as String, expected.message
            }

            verify key, spec, order
        }
    }

    @Test
    void testAssertValidRSAVerificationKeyHappyPath() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isRsa() }) {

            RSAPrivateKey key = createMock(RSAPrivateKey)
            BigInteger modulus = createMock(BigInteger)
            expect(key.getModulus()).andStubReturn(modulus)
            expect(modulus.bitLength()).andStubReturn(alg.minKeyLength)

            replay key, modulus

            alg.assertValidVerificationKey(key)

            verify key, modulus
        }
    }

    @Test
    void testAssertValidRSAVerificationKeyNotRSAKey() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isRsa() }) {

            PrivateKey key = createMock(PrivateKey)

            try {
                alg.assertValidVerificationKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals 'RSA verification keys must be RSAKey instances.', expected.message
            }
        }
    }

    @Test
    void testAssertValidRSAVerificationKeyInsufficientKeyLength() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values().findAll { it.isRsa() }) {

            String section = alg.name().startsWith("P") ? "3.5" : "3.3"

            RSAPrivateKey key = createMock(RSAPrivateKey)
            BigInteger modulus = createMock(BigInteger)
            expect(key.getModulus()).andStubReturn(modulus)
            expect(modulus.bitLength()).andStubReturn(alg.minKeyLength - 8) //one less byte

            replay key, modulus

            try {
                alg.assertValidVerificationKey(key)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals "The verification key's size is ${modulus.bitLength()} bits which is not secure enough " +
                        "for the ${alg.name()} algorithm.  The JWT JWA Specification " +
                        "(RFC 7518, Section ${section}) states that keys used with ${alg.name()} MUST have a size >= " +
                        "${alg.minKeyLength} bits.  Consider using the ${Keys.class.getName()} class's " +
                        "'keyPairFor(SignatureAlgorithm.${alg.name()})' method to create a key pair guaranteed " +
                        "to be secure enough for ${alg.name()}.  See " +
                        "https://tools.ietf.org/html/rfc7518#section-${section} for more information." as String, expected.message
            }

            verify key, modulus
        }
    }
}
