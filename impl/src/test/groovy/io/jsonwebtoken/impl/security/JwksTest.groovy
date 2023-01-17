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

import io.jsonwebtoken.impl.lang.Converters
import io.jsonwebtoken.impl.lang.RedactedSupplier
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders
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
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint

import static org.junit.Assert.*

class JwksTest {

    private static final SecretKey SKEY = JwsAlgorithms.HS256.keyBuilder().build()
    private static final java.security.KeyPair EC_PAIR = JwsAlgorithms.ES256.keyPairBuilder().build()

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
        def builder = Jwks.builder().forKey(key)
        builder."set${cap}"(val)
        def jwk = builder.build()
        assertEquals val, jwk."get${cap}"()
        assertEquals expectedFieldValue, jwk."${id}"

        //test null value:
        builder = Jwks.builder().forKey(key)
        try {
            builder."set${cap}"(null)
            fail("IAE should have been thrown")
        } catch (IllegalArgumentException ignored) {
        }
        jwk = builder.build()
        assertNull jwk."get${cap}"()
        assertNull jwk."$id"
        assertFalse jwk.containsKey(id)

        //test empty string value
        builder = Jwks.builder().forKey(key)
        if (val instanceof String) {
            try {
                builder."set${cap}"('   ' as String)
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
                builder."set${cap}"(val)
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
        def jwk = Jwks.builder().forKey(SKEY).build()
        assertEquals 'oct', jwk.getType()
        assertEquals 'oct', jwk.kty
        assertNotNull jwk.k
        assertTrue jwk.k instanceof RedactedSupplier
        assertTrue MessageDigest.isEqual(SKEY.encoded, Decoders.BASE64URL.decode(jwk.k.get()))
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
        testProperty('operations', 'key_ops', ['foo', 'bar'] as Set<String>)
    }

    @Test
    void testPublicKeyUse() {
        testProperty('publicKeyUse', 'use', srandom())
    }

    @Test
    void testX509CertChain() {
        //get a test cert:
        X509Certificate cert = TestKeys.forAlgorithm(JwsAlgorithms.RS256).cert
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
        def jwk = Jwks.builder().forKey(SKEY).setRandom(random).build()
        assertSame random, jwk.@context.getRandom()
    }

    @Test(expected = IllegalArgumentException)
    void testNullRandom() {
        Jwks.builder().forKey(SKEY).setRandom(null).build()
    }

    static void testX509Thumbprint(int number) {
        def algs = JwsAlgorithms.values().findAll { it instanceof SignatureAlgorithm }

        for (def alg : algs) {
            //get test cert:
            X509Certificate cert = TestCertificates.readTestCertificate(alg)
            def pubKey = cert.getPublicKey()

            def builder = Jwks.builder()
            if (pubKey instanceof ECKey) {
                builder = builder.forEcChain(cert)
            } else if (pubKey instanceof RSAKey) {
                builder = builder.forRsaChain(cert)
            } else {
                builder = builder.forOctetChain(cert)
            }

            if (number == 1) {
                builder.withX509Sha1Thumbprint(true)
            } // otherwise, when a chain is present, a sha256 thumbprint is calculated automatically

            def jwkFromKey = builder.build() as PublicJwk
            byte[] thumbprint = jwkFromKey."getX509CertificateSha${number}Thumbprint"()
            assertNotNull thumbprint

            //ensure base64url encoding/decoding of the thumbprint works:
            def jwkFromValues = Jwks.builder().putAll(jwkFromKey).build() as PublicJwk
            assertArrayEquals thumbprint, jwkFromValues."getX509CertificateSha${number}Thumbprint"()
        }
    }

    @Test
    void testSecretJwks() {
        Collection<MacAlgorithm> algs = JwsAlgorithms.values().findAll({ it instanceof MacAlgorithm }) as Collection<MacAlgorithm>
        for (def alg : algs) {
            SecretKey secretKey = alg.keyBuilder().build()
            def jwk = Jwks.builder().forKey(secretKey).setId('id').build()
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
            Jwks.builder().forKey(key).build()
            fail()
        } catch (UnsupportedKeyException expected) {
            String expectedMsg = 'Unable to encode SecretKey to JWK: ' + SecretJwkFactory.ENCODED_UNAVAILABLE_MSG
            assertEquals expectedMsg, expected.getMessage()
            assertTrue expected.getCause() instanceof IllegalArgumentException
            assertEquals SecretJwkFactory.ENCODED_UNAVAILABLE_MSG, expected.getCause().getMessage()
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
            Jwks.builder().forKey(key).build()
            fail()
        } catch (UnsupportedKeyException expected) {
            String expectedMsg = 'Unable to encode SecretKey to JWK: ' + SecretJwkFactory.ENCODED_UNAVAILABLE_MSG
            assertEquals expectedMsg, expected.getMessage()
            assertTrue expected.getCause() instanceof IllegalArgumentException
            assertEquals SecretJwkFactory.ENCODED_UNAVAILABLE_MSG, expected.getCause().getMessage()
            assertSame encodedEx, expected.getCause().getCause()
        }
    }

    @Test
    void testAsymmetricJwks() {

        Collection<KeyPairBuilderSupplier> algs = JwsAlgorithms.values().findAll({ it instanceof SignatureAlgorithm }) as Collection<SignatureAlgorithm>

        for (def alg : algs) {

            def pair = alg.keyPairBuilder().build()
            PublicKey pub = pair.getPublic()
            PrivateKey priv = pair.getPrivate()

            // test individual keys
            PublicJwk pubJwk = Jwks.builder().forKey(pub).setPublicKeyUse("sig").build()
            assertEquals pub, pubJwk.toKey()

            def builder = Jwks.builder().forKey(priv).setPublicKeyUse('sig')
            if (alg instanceof EdSignatureAlgorithm) {
                // We haven't implemented EdDSA public-key derivation yet, so public key is required
                builder.setPublicKey(pub)
            }
            PrivateJwk privJwk = builder.build()
            assertEquals priv, privJwk.toKey()
            PublicJwk privPubJwk = privJwk.toPublicJwk()
            assertEquals pubJwk, privPubJwk
            assertEquals pub, pubJwk.toKey()
            def jwkPair = privJwk.toKeyPair()
            assertEquals pub, jwkPair.getPublic()
            assertEquals priv, jwkPair.getPrivate()

            // test pair
            if (pub instanceof ECKey) {
                builder = Jwks.builder().forEcKeyPair(pair)
            } else if (pub instanceof RSAKey) {
                builder = Jwks.builder().forRsaKeyPair(pair)
            } else {
                builder = Jwks.builder().forOctetKeyPair(pair)
            }
            privJwk = builder.setPublicKeyUse("sig").build()
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
    void testOctetKeyPairs() {

        for (EdwardsCurve curve : EdwardsCurve.VALUES) {

            def pair = curve.keyPairBuilder().build()
            PublicKey pub = pair.getPublic()
            PrivateKey priv = pair.getPrivate()

            // test individual keys
            PublicJwk pubJwk = Jwks.builder().forKey(pub).setPublicKeyUse("sig").build()
            PublicJwk pubValuesJwk = Jwks.builder().putAll(pubJwk).build() as PublicJwk // ensure value map symmetry
            assertEquals pubJwk, pubValuesJwk
            assertEquals pub, pubJwk.toKey()
            assertEquals pub, pubValuesJwk.toKey()

            PrivateJwk privJwk = Jwks.builder().forKey(priv).setPublicKey(pub).setPublicKeyUse("sig").build()
            PrivateJwk privValuesJwk = Jwks.builder().putAll(privJwk).build() as PrivateJwk // ensure value map symmetry
            assertEquals privJwk, privValuesJwk
            assertEquals priv, privJwk.toKey()
            // we can't assert that priv.equals(privValuesJwk.toKey()) here because BouncyCastle uses PKCS8 V2 encoding
            // while the JDK uses V1, and BC implementations check that the encodings are equal (instead of their
            // actual key material).  Since we only care about the key material for JWK representations, and not the
            // key's PKCS8 encoding, we check that their 'd' values are the same, not that the keys' encoding is:
            byte[] privMaterial = curve.getKeyMaterial(priv)
            byte[] jwkKeyMaterial = curve.getKeyMaterial(privValuesJwk.toKey())
            assertArrayEquals privMaterial, jwkKeyMaterial

            PublicJwk privPubJwk = privJwk.toPublicJwk()
            assertEquals pubJwk, privPubJwk
            assertEquals pubValuesJwk, privPubJwk
            assertEquals pub, pubJwk.toKey()

            def jwkPair = privJwk.toKeyPair()
            assertEquals pub, jwkPair.getPublic()
            assertEquals priv, jwkPair.getPrivate()
            jwkPair = privValuesJwk.toKeyPair()
            assertEquals pub, jwkPair.getPublic()
            // see comments above about material equality instead of encoding equality
            privMaterial = curve.getKeyMaterial(priv)
            jwkKeyMaterial = curve.getKeyMaterial(jwkPair.getPrivate())
            assertArrayEquals privMaterial, jwkKeyMaterial

            // Test public-to-private builder coercion:
            privJwk = Jwks.builder().forKey(pub).setPrivateKey(priv).setPublicKeyUse('sig').build()
            privValuesJwk = Jwks.builder().putAll(privJwk).build() as PrivateJwk // ensure value map symmetry
            assertEquals privJwk, privValuesJwk
            assertEquals priv, privJwk.toKey()
            // see comments above about material equality instead of encoding equality
            privMaterial = curve.getKeyMaterial(priv)
            jwkKeyMaterial = curve.getKeyMaterial(jwkPair.getPrivate())
            assertArrayEquals privMaterial, jwkKeyMaterial

            privPubJwk = privJwk.toPublicJwk()
            pubValuesJwk = privValuesJwk.toPublicJwk()
            assertEquals pubJwk, privPubJwk
            assertEquals pubJwk, pubValuesJwk
            assertEquals pub, pubJwk.toKey()
            assertEquals pub, pubValuesJwk.toKey()

            // test pair
            privJwk = Jwks.builder().forOctetKeyPair(pair).setPublicKeyUse("sig").build()
            assertEquals priv, privJwk.toKey()
            // see comments above about material equality instead of encoding equality
            privMaterial = curve.getKeyMaterial(priv)
            jwkKeyMaterial = curve.getKeyMaterial(privValuesJwk.toKey())
            assertArrayEquals privMaterial, jwkKeyMaterial

            privPubJwk = privJwk.toPublicJwk()
            assertEquals pubJwk, privPubJwk
            assertEquals pubValuesJwk, privPubJwk
            assertEquals pub, pubJwk.toKey()

            jwkPair = privJwk.toKeyPair()
            assertEquals pub, jwkPair.getPublic()
            assertEquals priv, jwkPair.getPrivate()
        }
    }

    @Test
    void testUnknownCurveId() {
        def b = Jwks.builder()
                .put(AbstractJwk.KTY.getId(), DefaultOctetPublicJwk.TYPE_VALUE)
                .put(DefaultOctetPublicJwk.CRV.getId(), 'foo')
        try {
            b.build()
            fail()
        } catch (UnsupportedKeyException e) {
            String msg = "Unrecognized OKP JWK ${DefaultOctetPublicJwk.CRV} value 'foo'" as String
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testInvalidEcCurvePoint() {
        def algs = [JwsAlgorithms.ES256, JwsAlgorithms.ES384, JwsAlgorithms.ES512]

        for (SignatureAlgorithm alg : algs) {

            def pair = alg.keyPairBuilder().build()
            ECPublicKey pubKey = pair.getPublic() as ECPublicKey

            EcPublicJwk jwk = Jwks.builder().forKey(pubKey).build()

            //try creating a JWK with a bad point:
            def badPubKey = new InvalidECPublicKey(pubKey)
            try {
                Jwks.builder().forKey(badPubKey).build()
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
                    Jwks.builder().putAll(modified).build()
                } catch (InvalidKeyException ike) {
                    String expected = EcPublicJwkFactory.jwkContainsErrorMessage(jwk.crv as String, modified)
                    assertEquals(expected, ike.getMessage())
                }
            }
            for (def y : outOfFieldRange) {
                Map<String, ?> modified = new LinkedHashMap<>(jwk)
                modified.put('y', Converters.BIGINT.applyTo(y))
                try {
                    Jwks.builder().putAll(modified).build()
                } catch (InvalidKeyException ike) {
                    String expected = EcPublicJwkFactory.jwkContainsErrorMessage(jwk.crv as String, modified)
                    assertEquals(expected, ike.getMessage())
                }
            }
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
