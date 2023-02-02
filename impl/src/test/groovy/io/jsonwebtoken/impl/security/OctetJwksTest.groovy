package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.*
import org.junit.Test

import java.security.PrivateKey
import java.security.PublicKey

import static org.junit.Assert.*

class OctetJwksTest {

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

    /**
     * Asserts that a Jwk built with an Edwards Curve private key does not accept an Edwards Curve public key
     * on a different curve
     */
    @Test
    void testPrivateKeyCurvePublicKeyMismatch() {
        def priv = TestKeys.X448.pair.private
        def mismatchedPub = TestKeys.X25519.pair.public
        try {
            Jwks.builder().forKey(priv).setPublicKey(mismatchedPub).build()
            fail()
        } catch (InvalidKeyException ike) {
            String msg = "Specified Edwards Curve PublicKey does not match the PrivateKey curve."
            assertEquals msg, ike.getMessage()
        }
    }
}
