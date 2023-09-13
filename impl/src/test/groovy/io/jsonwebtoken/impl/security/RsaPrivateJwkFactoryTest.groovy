/*
 * Copyright (C) 2022 jsonwebtoken.io
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

import io.jsonwebtoken.impl.lang.Converters
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.RsaPrivateJwk
import io.jsonwebtoken.security.UnsupportedKeyException
import org.junit.Test

import java.security.interfaces.RSAMultiPrimePrivateCrtKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.KeySpec
import java.security.spec.RSAMultiPrimePrivateCrtKeySpec
import java.security.spec.RSAOtherPrimeInfo

import static org.junit.Assert.*

class RsaPrivateJwkFactoryTest {

    @Test
    void testGetPublicExponentFailure() {

        def key = new TestRSAPrivateKey(null) {
            @Override
            BigInteger getModulus() {
                return null
            }
        }

        try {
            Jwks.builder().key(key).build()
            fail()
        } catch (UnsupportedKeyException expected) {
            String msg = String.format(RsaPrivateJwkFactory.PUB_EXPONENT_EX_MSG, KeysBridge.toString(key))
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testFailedPublicKeyDerivation() {
        def key = new RSAPrivateCrtKey() {
            @Override
            BigInteger getPublicExponent() {
                return BigInteger.ZERO
            }

            @Override
            BigInteger getPrimeP() {
                return null
            }

            @Override
            BigInteger getPrimeQ() {
                return null
            }

            @Override
            BigInteger getPrimeExponentP() {
                return null
            }

            @Override
            BigInteger getPrimeExponentQ() {
                return null
            }

            @Override
            BigInteger getCrtCoefficient() {
                return null
            }

            @Override
            BigInteger getPrivateExponent() {
                return null
            }

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

            @Override
            BigInteger getModulus() {
                return BigInteger.ZERO
            }
        } as RSAPrivateKey

        try {
            Jwks.builder().key(key).build()
            fail()
        } catch (InvalidKeyException expected) {
            String prefix = 'Unable to derive RSAPublicKey from RSAPrivateKey {kty=RSA}. Cause: '
            assertTrue expected.getMessage().startsWith(prefix)
        }
    }

    @Test
    void testMultiPrimePrivateKey() {
        def pair = TestKeys.RS256.pair
        RSAPrivateCrtKey priv = pair.private as RSAPrivateCrtKey

        def info1 = new RSAOtherPrimeInfo(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE)
        def info2 = new RSAOtherPrimeInfo(BigInteger.TEN, BigInteger.TEN, BigInteger.TEN)
        def infos = [info1, info2]

        //build up test key:
        RSAMultiPrimePrivateCrtKey key = new TestRSAMultiPrimePrivateCrtKey(priv, infos)

        RsaPrivateJwk jwk = Jwks.builder().key(key).build()

        List<RSAOtherPrimeInfo> oth = jwk.get('oth') as List<RSAOtherPrimeInfo>
        assertTrue oth instanceof List
        assertEquals 2, oth.size()

        Map one = oth.get(0) as Map
        assertEquals one.r, RSAOtherPrimeInfoConverter.PRIME_FACTOR.applyTo(info1.prime)
        assertEquals one.d, RSAOtherPrimeInfoConverter.FACTOR_CRT_EXPONENT.applyTo(info1.crtCoefficient)
        assertEquals one.t, RSAOtherPrimeInfoConverter.FACTOR_CRT_COEFFICIENT.applyTo(info1.crtCoefficient)

        Map two = oth.get(1) as Map
        assertEquals two.r, RSAOtherPrimeInfoConverter.PRIME_FACTOR.applyTo(info2.prime)
        assertEquals two.d, RSAOtherPrimeInfoConverter.FACTOR_CRT_EXPONENT.applyTo(info2.crtCoefficient)
        assertEquals two.t, RSAOtherPrimeInfoConverter.FACTOR_CRT_COEFFICIENT.applyTo(info2.crtCoefficient)
    }

    @Test
    void testMultiPrimePrivateKeyWithoutExtraInfo() {
        def pair = TestKeys.RS256.pair
        RSAPrivateCrtKey priv = pair.private as RSAPrivateCrtKey
        RSAPublicKey pub = pair.public as RSAPublicKey

        RsaPrivateJwk jwk = Jwks.builder().key(priv).publicKey(pub).build()
        // an RSAMultiPrimePrivateCrtKey without OtherInfo elements is treated the same as a normal RSAPrivateCrtKey,
        // so ensure they are equal:
        RSAMultiPrimePrivateCrtKey key = new TestRSAMultiPrimePrivateCrtKey(priv, null)
        RsaPrivateJwk jwk2 = Jwks.builder().key(key).publicKey(pub).build()
        assertEquals jwk, jwk2
        assertNull jwk.get(DefaultRsaPrivateJwk.OTHER_PRIMES_INFO.getId())
        assertNull jwk2.get(DefaultRsaPrivateJwk.OTHER_PRIMES_INFO.getId())
    }

    @Test
    void testNonCrtPrivateKey() {
        //tests a standard RSAPrivateKey (not a RSAPrivateCrtKey or RSAMultiPrimePrivateCrtKey):
        def pair = TestKeys.RS256.pair
        RSAPrivateCrtKey privCrtKey = pair.private as RSAPrivateCrtKey
        RSAPublicKey pub = pair.public as RSAPublicKey

        def priv = new TestRSAPrivateKey(privCrtKey)

        RsaPrivateJwk jwk = Jwks.builder().key(priv).publicKey(pub).build()
        assertEquals 4, jwk.size() // kty, public exponent, modulus, private exponent
        assertEquals 'RSA', jwk.getType()
        assertEquals Converters.BIGINT.applyTo(pub.getModulus()), jwk.get(DefaultRsaPublicJwk.MODULUS.getId())
        assertEquals Converters.BIGINT.applyTo(pub.getPublicExponent()), jwk.get(DefaultRsaPublicJwk.PUBLIC_EXPONENT.getId())
        assertEquals Converters.BIGINT.applyTo(priv.getPrivateExponent()), jwk.get(DefaultRsaPrivateJwk.PRIVATE_EXPONENT.getId()).get()
    }

    @Test
    void testCreateJwkFromMinimalValues() { // no optional private values
        def pair = TestKeys.RS256.pair
        RSAPublicKey pub = pair.public as RSAPublicKey
        RSAPrivateKey priv = new TestRSAPrivateKey(pair.private as RSAPrivateKey)
        def jwk = Jwks.builder().key(priv).publicKey(pub).build()
        //minimal values: kty, modulus, public exponent, private exponent = 4 params:
        assertEquals 4, jwk.size()
        def map = new LinkedHashMap(jwk)
        assertEquals 4, map.size()

        def jwkFromValues = Jwks.builder().add(map).build()

        //ensure they're equal:
        assertEquals jwk, jwkFromValues
    }

    @Test
    void testCreateJwkFromMultiPrimeValues() {
        def pair = TestKeys.RS256.pair
        RSAPrivateCrtKey priv = pair.private as RSAPrivateCrtKey
        RSAPublicKey pub = pair.public as RSAPublicKey

        def info1 = new RSAOtherPrimeInfo(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE)
        def info2 = new RSAOtherPrimeInfo(BigInteger.TEN, BigInteger.TEN, BigInteger.TEN)
        def infos = [info1, info2]
        RSAMultiPrimePrivateCrtKey key = new TestRSAMultiPrimePrivateCrtKey(priv, infos)

        final RsaPrivateJwk jwk = Jwks.builder().key(key).publicKey(pub).build()

        //we have to test the class directly and override, since the dummy MultiPrime values won't be accepted by the
        //JVM:
        def factory = new RsaPrivateJwkFactory() {
            @Override
            protected RSAPrivateKey generateFromSpec(JwkContext<RSAPrivateKey> ctx, KeySpec keySpec) {
                assertTrue keySpec instanceof RSAMultiPrimePrivateCrtKeySpec
                RSAMultiPrimePrivateCrtKeySpec spec = (RSAMultiPrimePrivateCrtKeySpec) keySpec
                assertEquals key.modulus, spec.modulus
                assertEquals key.publicExponent, spec.publicExponent
                assertEquals key.privateExponent, spec.privateExponent
                assertEquals key.primeP, spec.primeP
                assertEquals key.primeQ, spec.primeQ
                assertEquals key.primeExponentP, spec.primeExponentP
                assertEquals key.primeExponentQ, spec.primeExponentQ
                assertEquals key.crtCoefficient, spec.crtCoefficient

                for (int i = 0; i < infos.size(); i++) {
                    RSAOtherPrimeInfo orig = infos.get(i)
                    RSAOtherPrimeInfo copy = spec.otherPrimeInfo[i]
                    assertEquals orig.prime, copy.prime
                    assertEquals orig.exponent, copy.exponent
                    assertEquals orig.crtCoefficient, copy.crtCoefficient

                }
                return new TestRSAMultiPrimePrivateCrtKey(priv, infos)
            }
        }

        def returned = factory.createJwkFromValues(jwk.@context)

        assertEquals jwk, returned
    }

}
