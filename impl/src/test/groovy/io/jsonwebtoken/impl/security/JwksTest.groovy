package io.jsonwebtoken.impl.security


import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.EllipticCurveSignatureAlgorithm
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.SignatureAlgorithms
import org.junit.Test

import javax.crypto.SecretKey
import java.security.KeyPair
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.*

class JwksTest {

    private static final SecretKey SKEY = SignatureAlgorithms.HS256.generateKey();
    private static final KeyPair EC_PAIR = SignatureAlgorithms.ES256.generateKeyPair();

    private static String srandom() {
        byte[] random = new byte[16];
        Randoms.secureRandom().nextBytes(random)
        return Encoders.BASE64URL.encode(random);
    }

    static void testProperty(String name, String id, def val) {
        String cap = "${name.capitalize()}"
        def key = name == 'use' ? EC_PAIR.public : SKEY

        //test non-null value:
        def builder = Jwks.builder().setKey(key)
        builder."set${cap}"(val)
        def jwk = builder.build()
        assertEquals val, jwk."get${cap}"()
        assertEquals val, jwk."${id}"

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
    void testUse() {
        testProperty('use', 'use', srandom())
    }

    @Test
    void testX509CertChain() {
        //get a test cert:
        X509Certificate cert = CertUtils.readTestCertificate(SignatureAlgorithms.RS256)
        testProperty('x509CertificateChain', 'x5c', cert)
    }

    @Test
    void testAPI() {
        def pair = SignatureAlgorithms.ES256.generateKeyPair();
        ECPublicKey ecPub = pair.getPublic() as ECPublicKey
        ECPrivateKey ecPriv = pair.getPrivate() as ECPrivateKey

        pair = SignatureAlgorithms.RS256.generateKeyPair()
        RSAPublicKey rsaPub = pair.getPublic() as RSAPublicKey
        RSAPrivateKey rsaPriv = pair.getPrivate() as RSAPrivateKey

        SecretKey secretKey = SignatureAlgorithms.HS256.generateKey()

        def ecPubJwk = Jwks.builder().setKey(ecPub).setPublicKeyUse("sig").build()
        assertEquals ecPub, ecPubJwk.toKey()

        def rsaPrivJwk = Jwks.builder().setKey(rsaPub).setPublicKeyUse("foo").setPrivateKey(rsaPriv).build();

        def ecPrivJwk = Jwks.builder().setKey(ecPriv).build()
        def pubJwk = ecPrivJwk.toPublicJwk()
        assertEquals ecPubJwk, pubJwk
        assertEquals ecPub, ecPrivJwk.toPublicKey()

        def rsaPubJwk = Jwks.builder().setKey(rsaPub).build()
        rsaPrivJwk = Jwks.builder().setKey(rsaPriv).setPublicKey(rsaPub).build()
        assertEquals rsaPubJwk, rsaPrivJwk.toPublicJwk()
    }

    @Test
    void testSecretKeyConversionHappyPath() {
        def algs = [SignatureAlgorithms.HS256, SignatureAlgorithms.HS384, SignatureAlgorithms.HS512]
        for (def alg : algs) {
            SecretKey key = alg.generateKey();
            def jwk = Jwks.builder().setKey(key).build()
            def result = Jwks.builder().putAll(jwk).build()
            assertArrayEquals key.encoded, result.toKey().encoded
        }
    }

    @Test
    void testEcConversionHappyPath() {

        List<EllipticCurveSignatureAlgorithm> algs = [SignatureAlgorithms.ES256, SignatureAlgorithms.ES384, SignatureAlgorithms.ES512]

        for (EllipticCurveSignatureAlgorithm alg : algs) {

            def pair = alg.generateKeyPair()
            ECPublicKey pubKey = (ECPublicKey) pair.getPublic();
            ECPrivateKey privKey = (ECPrivateKey) pair.getPrivate();

            def jwk = Jwks.builder().setKey(pubKey).build()
            def result = Jwks.builder().putAll(jwk).build()
            assertEquals pubKey, result.toKey()

            jwk = Jwks.builder().setKey(privKey).build()
            result = Jwks.builder().putAll(jwk).build()
            assertEquals privKey, result.toKey()
        }
    }
}
