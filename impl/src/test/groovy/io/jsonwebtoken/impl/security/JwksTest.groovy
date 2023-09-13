/*
 * Copyright (C) 2018 jsonwebtoken.io
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

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.lang.Converters
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Collections
import io.jsonwebtoken.security.*
import org.junit.Test

import javax.crypto.SecretKey
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.interfaces.ECKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint

import static org.junit.Assert.*

class JwksTest {

    private static final SecretKey SKEY = Jwts.SIG.HS256.key().build()
    private static final java.security.KeyPair EC_PAIR = Jwts.SIG.ES256.keyPair().build()

    private static String srandom() {
        byte[] random = new byte[16]
        Randoms.secureRandom().nextBytes(random)
        return Encoders.BASE64URL.encode(random)
    }

    static void testProperty(String name, String id, def val, def expectedFieldValue = val) {
        String cap = "${name.capitalize()}"
        def key = name == 'publicKeyUse' || name == 'x509CertificateChain' ? EC_PAIR.public : SKEY

        //test non-null value:
        //noinspection GroovyAssignabilityCheck
        def builder = Jwks.builder().key(key).delete('alg') // delete alg put there by SecretKeyBuilder
        builder."$name"(val)
        def jwk = builder.build()
        assertEquals val, jwk."get${cap}"()
        assertEquals expectedFieldValue, jwk."${id}"

        //test null value:
        builder = Jwks.builder().key(key).delete('alg')
        try {
            builder."$name"(null)
            fail("IAE should have been thrown")
        } catch (IllegalArgumentException ignored) {
        }
        jwk = builder.build()
        assertNull jwk."get${cap}"()
        assertNull jwk."$id"
        assertFalse jwk.containsKey(id)

        //test empty string value
        builder = Jwks.builder().key(key).delete('alg')
        if (val instanceof String) {
            try {
                builder."$name"('   ' as String)
                fail("IAE should have been thrown")
            } catch (IllegalArgumentException ignored) {
            }
            jwk = builder.build()
            assertNull jwk."get${cap}"()
            assertNull jwk."$id"
            assertFalse jwk.containsKey(id)
        }

        //test empty value
        if (val instanceof List) {
            val = Collections.emptyList()
        } else if (val instanceof Set) {
            val = Collections.emptySet()
        }
        if (val instanceof Collection) {
            try {
                builder."$name"(val)
                fail("IAE should have been thrown")
            } catch (IllegalArgumentException ignored) {
            }
            jwk = builder.build()
            assertNull jwk."get${cap}"()
            assertNull jwk."$id"
            assertFalse jwk.containsKey(id)
        }
    }

    @Test
    void testPrivateCtor() {
        new Jwks() // for code coverage only
    }

    @Test
    void testBuilderWithoutState() {
        try {
            Jwks.builder().build()
            fail()
        } catch (IllegalStateException ise) {
            String msg = 'A java.security.Key or one or more name/value pairs must be provided to create a JWK.'
            assertEquals msg, ise.getMessage()
        }
    }

    @Test
    void testBuilderWithSecretKey() {
        def jwk = Jwks.builder().key(SKEY).build()
        assertEquals 'oct', jwk.getType()
        assertEquals 'oct', jwk.kty
        String k = jwk.k.get() as String
        assertNotNull k
        assertTrue MessageDigest.isEqual(SKEY.encoded, Decoders.BASE64URL.decode(k))
    }

    @Test
    void testAlgorithm() {
        testProperty('algorithm', 'alg', srandom())
    }

    @Test
    void testId() {
        testProperty('id', 'kid', srandom())
    }

    @Test
    void testOperations() {
        def val = [Jwks.OP.SIGN, Jwks.OP.VERIFY] as Set<KeyOperation>
        def canonical = Collections.setOf('sign', 'verify')
        testProperty('operations', 'key_ops', val, canonical)
    }

    @Test
    void testPublicKeyUse() {
        testProperty('publicKeyUse', 'use', srandom())
    }

    @Test
    void testX509CertChain() {
        //get a test cert:
        X509Certificate cert = TestKeys.forAlgorithm(Jwts.SIG.RS256).cert
        def sval = JwtX509StringConverter.INSTANCE.applyTo(cert)
        testProperty('x509CertificateChain', 'x5c', [cert], [sval])
    }

    @Test
    void testX509Sha1Thumbprint() {
        testX509Thumbprint(1)
    }

    @Test
    void testX509Sha256Thumbprint() {
        testX509Thumbprint(256)
    }

    @Test
    void testRandom() {
        def random = new SecureRandom()
        def jwk = Jwks.builder().key(SKEY).random(random).build()
        assertSame random, jwk.@context.getRandom()
    }

    @Test
    void testNullRandom() {
        assertNotNull Jwks.builder().key(SKEY).random(null).build()
    }

    static void testX509Thumbprint(int number) {
        def algs = Jwts.SIG.get().values().findAll { it instanceof SignatureAlgorithm }

        for (def alg : algs) {
            //get test cert:
            X509Certificate cert = TestKeys.forAlgorithm(alg).cert
            def builder = Jwks.builder().chain(Arrays.asList(cert))

            if (number == 1) {
                builder.withX509Sha1Thumbprint(true)
            } // otherwise, when a chain is present, a sha256 thumbprint is calculated automatically

            def jwkFromKey = builder.build() as PublicJwk
            byte[] thumbprint = jwkFromKey."getX509CertificateSha${number}Thumbprint"()
            assertNotNull thumbprint

            //ensure base64url encoding/decoding of the thumbprint works:
            def jwkFromValues = Jwks.builder().add(jwkFromKey).build() as PublicJwk
            assertArrayEquals thumbprint, jwkFromValues."getX509CertificateSha${number}Thumbprint"() as byte[]
        }
    }

    @Test
    void testSecretJwks() {
        Collection<MacAlgorithm> algs = Jwts.SIG.get().values().findAll({ it instanceof MacAlgorithm }) as Collection<MacAlgorithm>
        for (def alg : algs) {
            SecretKey secretKey = alg.key().build()
            def jwk = Jwks.builder().key(secretKey).id('id').build()
            assertEquals 'oct', jwk.getType()
            assertTrue jwk.containsKey('k')
            assertEquals 'id', jwk.getId()
            assertEquals secretKey, jwk.toKey()
        }
    }

    @Test
    void testSecretKeyGetEncodedReturnsNull() {
        SecretKey key = new TestSecretKey(algorithm: "AES")
        try {
            Jwks.builder().key(key).build()
            fail()
        } catch (InvalidKeyException expected) {
            String causeMsg = "Missing required encoded bytes for key [${KeysBridge.toString(key)}]."
            String msg = "Unable to encode SecretKey to JWK: $causeMsg"
            assertEquals msg, expected.message
            assertTrue expected.getCause() instanceof InvalidKeyException
            assertEquals causeMsg, expected.getCause().getMessage()
        }
    }

    @Test
    void testSecretKeyGetEncodedThrowsException() {
        String encodedMsg = "not allowed"
        def encodedEx = new UnsupportedOperationException(encodedMsg)
        SecretKey key = new TestSecretKey() {
            @Override
            byte[] getEncoded() {
                throw encodedEx
            }
        }
        try {
            Jwks.builder().key(key).build()
            fail()
        } catch (InvalidKeyException expected) {
            String causeMsg = "Cannot obtain required encoded bytes from key [${KeysBridge.toString(key)}]: $encodedMsg"
            String msg = "Unable to encode SecretKey to JWK: $causeMsg"
            assertEquals msg, expected.message
            assertTrue expected.getCause() instanceof InvalidKeyException
            assertEquals causeMsg, expected.cause.message
            assertSame encodedEx, expected.getCause().getCause()
        }
    }

    @Test
    void testAsymmetricJwks() {

        Collection<SignatureAlgorithm> algs = Jwts.SIG.get().values()
                .findAll({ it instanceof SignatureAlgorithm }) as Collection<SignatureAlgorithm>

        for (SignatureAlgorithm alg : algs) {

            def pair = alg.keyPair().build()
            PublicKey pub = pair.getPublic()
            PrivateKey priv = pair.getPrivate()

            // test individual keys
            PublicJwk pubJwk = Jwks.builder().key(pub).publicKeyUse("sig").build()
            assertEquals pub, pubJwk.toKey()

            def builder = Jwks.builder().key(priv).publicKeyUse('sig')
            PrivateJwk privJwk = builder.build()
            assertEquals priv, privJwk.toKey()
            PublicJwk privPubJwk = privJwk.toPublicJwk()
            assertEquals pubJwk, privPubJwk
            assertEquals pub, pubJwk.toKey()
            def jwkPair = privJwk.toKeyPair()
            assertEquals pub, jwkPair.getPublic()
            assertEquals priv, jwkPair.getPrivate()

            // test pair
            builder = Jwks.builder()
            if (pub instanceof ECKey) {
                builder = builder.ecKeyPair(pair)
            } else if (pub instanceof RSAKey) {
                builder = builder.rsaKeyPair(pair)
            } else {
                builder = builder.octetKeyPair(pair)
            }
            privJwk = builder.publicKeyUse("sig").build() as PrivateJwk
            assertEquals priv, privJwk.toKey()
            privPubJwk = privJwk.toPublicJwk()
            assertEquals pubJwk, privPubJwk
            assertEquals pub, pubJwk.toKey()
            jwkPair = privJwk.toKeyPair()
            assertEquals pub, jwkPair.getPublic()
            assertEquals priv, jwkPair.getPrivate()
        }
    }

    @Test
    void testInvalidEcCurvePoint() {
        def algs = [Jwts.SIG.ES256, Jwts.SIG.ES384, Jwts.SIG.ES512]

        for (SignatureAlgorithm alg : algs) {

            def pair = alg.keyPair().build()
            ECPublicKey pubKey = pair.getPublic() as ECPublicKey

            EcPublicJwk jwk = Jwks.builder().key(pubKey).build()

            //try creating a JWK with a bad point:
            def badPubKey = new InvalidECPublicKey(pubKey)
            try {
                Jwks.builder().key(badPubKey).build()
            } catch (InvalidKeyException ike) {
                String curveId = jwk.get('crv')
                String msg = EcPublicJwkFactory.keyContainsErrorMessage(curveId)
                assertEquals msg, ike.getMessage()
            }

            BigInteger p = pubKey.getParams().getCurve().getField().getP()
            def outOfFieldRange = [BigInteger.ZERO, BigInteger.ONE, p, p.add(BigInteger.valueOf(1))]
            for (def x : outOfFieldRange) {
                Map<String, ?> modified = new LinkedHashMap<>(jwk)
                modified.put('x', Converters.BIGINT.applyTo(x))
                try {
                    Jwks.builder().add(modified).build()
                } catch (InvalidKeyException ike) {
                    String expected = EcPublicJwkFactory.jwkContainsErrorMessage(jwk.crv as String, modified)
                    assertEquals(expected, ike.getMessage())
                }
            }
            for (def y : outOfFieldRange) {
                Map<String, ?> modified = new LinkedHashMap<>(jwk)
                modified.put('y', Converters.BIGINT.applyTo(y))
                try {
                    Jwks.builder().add(modified).build()
                } catch (InvalidKeyException ike) {
                    String expected = EcPublicJwkFactory.jwkContainsErrorMessage(jwk.crv as String, modified)
                    assertEquals(expected, ike.getMessage())
                }
            }
        }
    }

    @Test
    void testPublicJwkBuilderWithRSAPublicKey() {
        def key = TestKeys.RS256.pair.public
        // must cast to PublicKey to avoid Groovy's dynamic type dispatch to the key(RSAPublicKey) method:
        def jwk = Jwks.builder().key((PublicKey) key).build()
        assertNotNull jwk
        assertTrue jwk instanceof RsaPublicJwk
    }

    @Test
    void testPublicJwkBuilderWithECPublicKey() {
        def key = TestKeys.ES256.pair.public
        // must cast to PublicKey to avoid Groovy's dynamic type dispatch to the key(ECPublicKey) method:
        def jwk = Jwks.builder().key((PublicKey) key).build()
        assertNotNull jwk
        assertTrue jwk instanceof EcPublicJwk
    }

    @Test
    void testPublicJwkBuilderWithUnsupportedKey() {
        def key = new TestPublicKey()
        // must cast to PublicKey to avoid Groovy's dynamic type dispatch to the key(ECPublicKey) method:
        try {
            Jwks.builder().key((PublicKey) key)
        } catch (UnsupportedKeyException expected) {
            String msg = "There is no builder that supports specified key [${KeysBridge.toString(key)}]."
            assertEquals(msg, expected.getMessage())
            assertNotNull expected.getCause() // ensure we always retain a cause
        }
    }

    @Test
    void testPrivateJwkBuilderWithRSAPrivateKey() {
        def key = TestKeys.RS256.pair.private
        // must cast to PrivateKey to avoid Groovy's dynamic type dispatch to the key(RSAPrivateKey) method:
        def jwk = Jwks.builder().key((PrivateKey) key).build()
        assertNotNull jwk
        assertTrue jwk instanceof RsaPrivateJwk
    }

    @Test
    void testPrivateJwkBuilderWithECPrivateKey() {
        def key = TestKeys.ES256.pair.private
        // must cast to PrivateKey to avoid Groovy's dynamic type dispatch to the key(ECPrivateKey) method:
        def jwk = Jwks.builder().key((PrivateKey) key).build()
        assertNotNull jwk
        assertTrue jwk instanceof EcPrivateJwk
    }

    @Test
    void testPrivateJwkBuilderWithUnsupportedKey() {
        def key = new TestPrivateKey()
        try {
            Jwks.builder().key((PrivateKey) key)
        } catch (UnsupportedKeyException expected) {
            String msg = "There is no builder that supports specified key [${KeysBridge.toString(key)}]."
            assertEquals(msg, expected.getMessage())
            assertNotNull expected.getCause() // ensure we always retain a cause
        }
    }

    @Test
    void testEcChain() {
        TestKeys.EC.each {
            ECPublicKey key = it.pair.public as ECPublicKey
            def jwk = Jwks.builder().ecChain(it.chain).build()
            assertEquals key, jwk.toKey()
            assertEquals it.chain, jwk.getX509CertificateChain()
        }
    }

    @Test
    void testRsaChain() {
        TestKeys.RSA.each {
            RSAPublicKey key = it.pair.public as RSAPublicKey
            def jwk = Jwks.builder().rsaChain(it.chain).build()
            assertEquals key, jwk.toKey()
            assertEquals it.chain, jwk.getX509CertificateChain()
        }
    }

    @Test
    void testOctetChain() {
        TestKeys.EdEC.each { // no chains for XEC keys
            PublicKey key = it.pair.public
            def jwk = Jwks.builder().octetChain(it.chain).build()
            assertEquals key, jwk.toKey()
            assertEquals it.chain, jwk.getX509CertificateChain()
        }
    }

    @Test
    void testRsaKeyPair() {
        TestKeys.RSA.each {
            java.security.KeyPair pair = it.pair
            PrivateJwk jwk = Jwks.builder().rsaKeyPair(pair).build()
            assertEquals it.pair.public, jwk.toPublicJwk().toKey()
            assertEquals it.pair.private, jwk.toKey()
        }
    }

    @Test
    void testEcKeyPair() {
        TestKeys.EC.each {
            java.security.KeyPair pair = it.pair
            PrivateJwk jwk = Jwks.builder().ecKeyPair(pair).build()
            assertEquals it.pair.public, jwk.toPublicJwk().toKey()
            assertEquals it.pair.private, jwk.toKey()
        }
    }

    @Test
    void testOctetKeyPair() {
        TestKeys.EdEC.each {
            java.security.KeyPair pair = it.pair
            PrivateJwk jwk = Jwks.builder().octetKeyPair(pair).build()
            assertEquals it.pair.public, jwk.toPublicJwk().toKey()
            assertEquals it.pair.private, jwk.toKey()
        }
    }

    @Test
    void testKeyPair() {
        TestKeys.ASYM.each {
            java.security.KeyPair pair = it.pair
            PrivateJwk jwk = Jwks.builder().keyPair(pair).build()
            assertEquals it.pair.public, jwk.toPublicJwk().toKey()
            assertEquals it.pair.private, jwk.toKey()
        }
    }

    private static class InvalidECPublicKey implements ECPublicKey {

        private final ECPublicKey good

        InvalidECPublicKey(ECPublicKey good) {
            this.good = good
        }

        @Override
        ECPoint getW() {
            return ECPoint.POINT_INFINITY // bad value, should make all 'contains' validations fail
        }

        @Override
        String getAlgorithm() {
            return good.getAlgorithm()
        }

        @Override
        String getFormat() {
            return good.getFormat()
        }

        @Override
        byte[] getEncoded() {
            return good.getEncoded()
        }

        @Override
        ECParameterSpec getParams() {
            return good.getParams()
        }
    }
}
