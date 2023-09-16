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

import io.jsonwebtoken.impl.RfcTests
import io.jsonwebtoken.security.*
import org.junit.Test

import java.security.PrivateKey
import java.security.PublicKey

import static org.junit.Assert.*

class OctetJwksTest {

    /**
     * Test case discovered during CI testing where a randomly-generated X25519 public key with a leading zero byte
     * was not being decoded correctly.  This test asserts that this value is decoded correctly.
     */
    @Test
    void testX25519PublicJson() {
        String use = 'sig'
        String kty = 'OKP'
        String crv = 'X25519'
        String x = 'AHwi7xPo5meUAGBDyzLZ9_ZwmmYA_SAMpdRFnsmggnI'
        byte[] decoded = DefaultOctetPublicJwk.X.applyFrom(x)
        assertEquals 0x00, decoded[0]

        String json = RfcTests.stripws("""
        {
           "use": "$use",
           "kty": "$kty",
           "crv": "$crv",
           "x": "$x"
        }""")
        def jwk = Jwks.parser().build().parse(json) as OctetPublicJwk
        assertEquals use, jwk.getPublicKeyUse()
        assertEquals kty, jwk.getType()
        assertEquals crv, jwk.get('crv')
        assertEquals x, jwk.get('x')
    }

    /**
     * Test case discovered during CI testing where a randomly-generated Ed448 public key with a leading zero byte was
     * not being decoded correctly.  This test asserts that this value is decoded correctly.
     */
    @Test
    void testEd448PublicJson() {
        String use = 'sig'
        String kty = 'OKP'
        String crv = 'Ed448'
        String x = 'AKxj_Iz2y6IHq5KipsOYZJyUjClO1IbT396KQK15DFryNwowKKBvswQLWytxXHgqGkpG5PUWkuQA'
        byte[] decoded = DefaultOctetPublicJwk.X.applyFrom(x)
        assertEquals 0x00, decoded[0]

        String json = RfcTests.stripws("""
        {
           "use": "$use",
           "kty": "$kty",
           "crv": "$crv",
           "x": "$x"
        }""")
        def jwk = Jwks.parser().build().parse(json) as OctetPublicJwk
        assertEquals use, jwk.getPublicKeyUse()
        assertEquals kty, jwk.getType()
        assertEquals crv, jwk.get('crv')
        assertEquals x, jwk.get('x')
    }

    /**
     * Test case discovered during CI testing where a randomly-generated Ed25519 private key with a leading zero byte
     * was not being decoded correctly.  This test asserts that this value is decoded correctly.
     */
    @Test
    void testEd25519PrivateJson() {
        String use = 'sig'
        String kty = 'OKP'
        String crv = 'Ed25519'
        String x = '9NAzPLMakU0R-tLgX7NmzUUg_fUGiDbrGOWqQ0F_s3g'
        String d = 'AAfgb017BkHlLf_SqVBA_LqPhabpdh43dLXHfD6ggQ0'
        byte[] decoded = DefaultOctetPrivateJwk.D.applyFrom(d)
        assertEquals 0x00, decoded[0]
        String json = RfcTests.stripws("""
        {
           "use": "$use",
           "kty": "$kty",
           "crv": "$crv",
           "x": "$x",
           "d": "$d"
        }""")
        def jwk = Jwks.parser().build().parse(json) as OctetPrivateJwk
        assertEquals use, jwk.getPublicKeyUse()
        assertEquals kty, jwk.getType()
        assertEquals crv, jwk.get('crv')
        assertEquals x, jwk.get('x')
        assertEquals d, jwk.get('d').get() // Supplier
        def pubJwk = jwk.toPublicJwk()
        assertEquals use, pubJwk.getPublicKeyUse()
        assertEquals kty, pubJwk.getType()
        assertEquals crv, pubJwk.get('crv')
        assertEquals x, pubJwk.get('x')
        assertNull pubJwk.get('d')
    }

    @Test
    void testOctetKeyPairs() {

        for (EdwardsCurve curve : EdwardsCurve.VALUES) {

            def pair = curve.keyPair().build()
            PublicKey pub = pair.getPublic()
            PrivateKey priv = pair.getPrivate()

            // test individual keys
            PublicJwk pubJwk = Jwks.builder().octetKey(pub).publicKeyUse("sig").build()
            PublicJwk pubValuesJwk = Jwks.builder().add(pubJwk).build() as PublicJwk // ensure value map symmetry
            assertEquals pubJwk, pubValuesJwk
            assertEquals pub, pubJwk.toKey()
            assertEquals pub, pubValuesJwk.toKey()

            PrivateJwk privJwk = Jwks.builder().octetKey(priv).publicKey(pub).publicKeyUse("sig").build()
            PrivateJwk privValuesJwk = Jwks.builder().add(privJwk).build() as PrivateJwk // ensure value map symmetry
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
            privJwk = Jwks.builder().octetKey(pub).privateKey(priv).publicKeyUse('sig').build()
            privValuesJwk = Jwks.builder().add(privJwk).build() as PrivateJwk // ensure value map symmetry
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
            privJwk = Jwks.builder().octetKeyPair(pair).publicKeyUse("sig").build()
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
                .add(AbstractJwk.KTY.getId(), DefaultOctetPublicJwk.TYPE_VALUE)
                .add(DefaultOctetPublicJwk.CRV.getId(), 'foo')
        try {
            b.build()
            fail()
        } catch (UnsupportedKeyException e) {
            String msg = "Unrecognized OKP JWK ${DefaultOctetPublicJwk.CRV} value 'foo'" as String
            assertEquals msg, e.getMessage()
        }
    }

    /**
     * Asserts that a Jwk built with an Edwards Curve private key does not accept an Edwards Curve public key
     * on a different curve
     */
    @Test
    void testPrivateKeyCurvePublicKeyMismatch() {
        def priv = TestKeys.X448.pair.private
        def mismatchedPub = TestKeys.X25519.pair.public
        try {
            Jwks.builder().octetKey(priv).publicKey(mismatchedPub).build()
            fail()
        } catch (InvalidKeyException ike) {
            String msg = "Specified Edwards Curve PublicKey does not match the specified PrivateKey's curve."
            assertEquals msg, ike.getMessage()
        }
    }
}
