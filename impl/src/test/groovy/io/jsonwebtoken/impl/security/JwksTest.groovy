package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.Converters
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.AsymmetricKeySignatureAlgorithm
import io.jsonwebtoken.security.EcPublicJwk
import io.jsonwebtoken.security.EllipticCurveSignatureAlgorithm
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.PrivateJwk
import io.jsonwebtoken.security.PublicJwk
import io.jsonwebtoken.security.SecretKeySignatureAlgorithm
import io.jsonwebtoken.security.SignatureAlgorithms
import org.junit.Test

import javax.crypto.SecretKey
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.interfaces.ECKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint

import static org.junit.Assert.*

class JwksTest {

    private static final SecretKey SKEY = SignatureAlgorithms.HS256.generateKey();
    private static final KeyPair EC_PAIR = SignatureAlgorithms.ES256.generateKeyPair();

    private static String srandom() {
        byte[] random = new byte[16];
        Randoms.secureRandom().nextBytes(random)
        return Encoders.BASE64URL.encode(random);
    }

    static void testProperty(String name, String id, def val, def expectedFieldValue=val) {
        String cap = "${name.capitalize()}"
        def key = name == 'publicKeyUse' || name == 'x509CertificateChain' ? EC_PAIR.public : SKEY

        //test non-null value:
        def builder = Jwks.builder().setKey(key)
        builder."set${cap}"(val)
        def jwk = builder.build()
        assertEquals val, jwk."get${cap}"()
        assertEquals expectedFieldValue, jwk."${id}"

        //test null value:
        builder = Jwks.builder().setKey(key)
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
        builder = Jwks.builder().setKey(key)
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
        def jwk = Jwks.builder().setKey(SKEY).build()
        assertEquals 'oct', jwk.getType()
        assertEquals 'oct', jwk.kty
        assertNotNull jwk.k
        assertTrue jwk.k instanceof String
        assertTrue MessageDigest.isEqual(SKEY.encoded, Decoders.BASE64URL.decode(jwk.k as String))
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
        X509Certificate cert = CertUtils.readTestCertificate(SignatureAlgorithms.RS256)
        def sval = JwtX509StringConverter.INSTANCE.applyTo(cert)
        testProperty('x509CertificateChain', 'x5c', [cert], [sval])
    }

    @Test
    void testX509Sha1Thumbprint() {
        testThumbprint(1)
    }

    @Test
    void testX509Sha256Thumbprint() {
        testThumbprint(256)
    }

    static void testThumbprint(int number) {
        def algs = SignatureAlgorithms.values().findAll {it instanceof AsymmetricKeySignatureAlgorithm}

        for(def alg : algs) {
            //get test cert:
            X509Certificate cert = CertUtils.readTestCertificate(alg)
            def pubKey = cert.getPublicKey()

            def builder = pubKey instanceof RSAPublicKey ?
                    Jwks.builder().forRsaChain(cert) :
                    Jwks.builder().forEcChain(cert)

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
        Collection<SecretKeySignatureAlgorithm> algs = SignatureAlgorithms.values().findAll({it instanceof SecretKeySignatureAlgorithm}) as Collection<SecretKeySignatureAlgorithm>
        for(def alg : algs) {
            SecretKey secretKey = alg.generateKey()
            def jwk = Jwks.builder().setKey(secretKey).setId('id').build()
            assertEquals 'oct', jwk.getType()
            assertTrue jwk.containsKey('k')
            assertEquals 'id', jwk.getId()
            assertEquals secretKey, jwk.toKey()
        }
    }

    @Test
    void testAsymmetricJwks() {

        Collection<AsymmetricKeySignatureAlgorithm> algs = SignatureAlgorithms.values().findAll({it instanceof AsymmetricKeySignatureAlgorithm}) as Collection<AsymmetricKeySignatureAlgorithm>

        for(def alg : algs) {

            def pair = alg.generateKeyPair()
            PublicKey pub = pair.getPublic()
            PrivateKey priv = pair.getPrivate()

            // test individual keys
            PublicJwk pubJwk = Jwks.builder().setKey(pub).setPublicKeyUse("sig").build()
            assertEquals pub, pubJwk.toKey()
            PrivateJwk privJwk = Jwks.builder().setKey(priv).setPublicKeyUse("sig").build()
            assertEquals priv, privJwk.toKey()
            PublicJwk privPubJwk = privJwk.toPublicJwk()
            assertEquals pubJwk, privPubJwk
            assertEquals pub, pubJwk.toKey()
            def jwkPair = privJwk.toKeyPair()
            assertEquals pub, jwkPair.getPublic()
            assertEquals priv, jwkPair.getPrivate()

            // test pair
            privJwk = pub instanceof ECKey ?
                    Jwks.builder().setKeyPairEc(pair).setPublicKeyUse("sig").build() :
                    Jwks.builder().setKeyPairRsa(pair).setPublicKeyUse("sig").build()
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
    void testInvalidCurvePoint() {
        def algs = [SignatureAlgorithms.ES256, SignatureAlgorithms.ES384, SignatureAlgorithms.ES512]

        for(EllipticCurveSignatureAlgorithm alg : algs) {

            def pair = alg.generateKeyPair()
            ECPublicKey pubKey = pair.getPublic() as ECPublicKey

            EcPublicJwk jwk = Jwks.builder().setKey(pubKey).build()

            //try creating a JWK with a bad point:
            def badPubKey = new InvalidECPublicKey(pubKey)
            try {
                Jwks.builder().setKey(badPubKey).build()
            } catch (InvalidKeyException ike) {
                String curveId = jwk.get('crv')
                String msg = String.format(EcPublicJwkFactory.KEY_CONTAINS_FORMAT_MSG, curveId, curveId)
                assertEquals msg, ike.getMessage()
            }

            BigInteger p = pubKey.getParams().getCurve().getField().getP()
            def outOfFieldRange = [BigInteger.ZERO, BigInteger.ONE,p, p.add(BigInteger.valueOf(1))]
            for(def x : outOfFieldRange) {
                Map<String,?> modified = new LinkedHashMap<>(jwk)
                modified.put('x', Converters.BIGINT.applyTo(x))
                try {
                    Jwks.builder().putAll(modified).build()
                } catch (InvalidKeyException ike) {
                    String expected = String.format(EcPublicJwkFactory.JWK_CONTAINS_FORMAT_MSG, jwk.get('crv'), modified)
                    assertEquals(expected, ike.getMessage())
                }
            }
            for(def y : outOfFieldRange) {
                Map<String,?> modified = new LinkedHashMap<>(jwk)
                modified.put('y', Converters.BIGINT.applyTo(y))
                try {
                    Jwks.builder().putAll(modified).build()
                } catch (InvalidKeyException ike) {
                    String expected = String.format(EcPublicJwkFactory.JWK_CONTAINS_FORMAT_MSG, jwk.get('crv'), modified)
                    assertEquals(expected, ike.getMessage())
                }
            }
        }
    }

    private static class InvalidECPublicKey implements ECPublicKey {

        private final ECPublicKey good;

        InvalidECPublicKey(ECPublicKey good) {
            this.good = good;
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
