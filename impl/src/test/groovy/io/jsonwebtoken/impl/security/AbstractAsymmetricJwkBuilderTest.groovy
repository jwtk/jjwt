package io.jsonwebtoken.impl.security

import io.jsonwebtoken.lang.Assert
import io.jsonwebtoken.security.EcPrivateJwk
import io.jsonwebtoken.security.EcPublicJwk
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.RsaPublicJwkBuilder
import org.junit.Test

import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.*

class AbstractAsymmetricJwkBuilderTest {

    private static final X509Certificate CERT = TestKeys.RS256.cert
    private static final List<X509Certificate> CHAIN = [CERT]
    private static final RSAPublicKey PUB_KEY = CERT.getPublicKey() as RSAPublicKey

    private static RsaPublicJwkBuilder builder() {
        return Jwks.builder().setKey(PUB_KEY)
    }

    @Test
    void testUse() {
        def val = UUID.randomUUID().toString()
        def jwk = builder().setPublicKeyUse(val).build()
        assertEquals val, jwk.getPublicKeyUse()
        assertEquals val, jwk.use

        RSAPrivateKey privateKey = TestKeys.RS256.pair.private as RSAPrivateKey

        jwk = builder().setPublicKeyUse(val).setPrivateKey(privateKey).build()
        assertEquals val, jwk.getPublicKeyUse()
        assertEquals val, jwk.use
    }

    @Test
    void testX509Url() {
        def val = new URI(UUID.randomUUID().toString())
        assertSame val, builder().setX509Url(val).build().getX509Url()
    }

    @Test
    void testX509CertificateChain() {
        assertEquals CHAIN, builder().setX509CertificateChain(CHAIN).build().getX509CertificateChain()
    }

    @Test
    void testX509CertificateSha1Thumbprint() {
        def jwk = builder().setX509CertificateChain(CHAIN).withX509Sha1Thumbprint(true).build()
        Assert.notEmpty(jwk.getX509CertificateSha1Thumbprint())
        Assert.hasText(jwk.get(AbstractAsymmetricJwk.X5T.getId()) as String)
    }

    @Test
    void testX509CertificateSha256Thumbprint() {
        def jwk = builder().setX509CertificateChain(CHAIN).withX509Sha256Thumbprint(true).build()
        Assert.notEmpty(jwk.getX509CertificateSha256Thumbprint())
        Assert.hasText(jwk.get(AbstractAsymmetricJwk.X5T_S256.getId()) as String)
    }

    @Test
    void testEcPrivateJwkFromPublicBuilder() {
        def pair = TestKeys.ES256.pair

        //start with a public key builder
        def builder = Jwks.builder().setKey(pair.public as ECPublicKey)
        assertTrue builder instanceof AbstractAsymmetricJwkBuilder.DefaultEcPublicJwkBuilder

        //applying the private key turns it into a private key builder
        builder = builder.setPrivateKey(pair.private as ECPrivateKey)
        assertTrue builder instanceof AbstractAsymmetricJwkBuilder.DefaultEcPrivateJwkBuilder

        //building creates a private jwk:
        def jwk = builder.build()
        assertTrue jwk instanceof EcPrivateJwk

        //which also has information for the public key:
        jwk = jwk.toPublicJwk()
        assertTrue jwk instanceof EcPublicJwk
    }
}
