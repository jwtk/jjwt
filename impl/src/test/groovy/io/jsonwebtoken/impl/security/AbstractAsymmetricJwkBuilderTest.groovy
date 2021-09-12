package io.jsonwebtoken.impl.security


import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.RsaPublicJwkBuilder
import io.jsonwebtoken.security.SignatureAlgorithms
import org.junit.Test

import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.*

class AbstractAsymmetricJwkBuilderTest {

    private static final X509Certificate CERT = CertUtils.readTestCertificate(SignatureAlgorithms.RS256)
    private static final RSAPublicKey PUB_KEY = (RSAPublicKey)CERT.getPublicKey();

    private static RsaPublicJwkBuilder builder() {
        return Jwks.builder().setKey(PUB_KEY)
    }

    @Test
    void testUse() {
        def val = UUID.randomUUID().toString()
        def jwk = builder().setPublicKeyUse(val).build()
        assertEquals val, jwk.getPublicKeyUse()
        assertEquals val, jwk.use

        def privateKey = CertUtils.readTestPrivateKey(SignatureAlgorithms.RS256);

        jwk = builder().setPublicKeyUse(val).setPrivateKey((RSAPrivateKey)privateKey).build()
        assertEquals val, jwk.getPublicKeyUse()
        assertEquals val, jwk.use
    }

    @Test
    void testX509Url() {
        def val = new URI(UUID.randomUUID().toString())
        assertEquals val, builder().setX509Url(val).build().getX509Url()
    }

    @Test
    void testX509CertificateChain() {
        def a = UUID.randomUUID().toString()
        def b = UUID.randomUUID().toString()
        def val = [a, b] as List<String>
        assertEquals val, builder().setX509CertificateChain(val).build().getX509CertificateChain()
    }

    @Test
    void testX509CertificateSha1Thumbprint() {
        def val = UUID.randomUUID().toString()
        assertEquals val, builder().setX509CertificateSha1Thumbprint(val).build().getX509CertificateSha1Thumbprint()
    }

    @Test
    void testX509CertificateSha256Thumbprint() {
        def val = UUID.randomUUID().toString()
        assertEquals val, builder().setX509CertificateSha256Thumbprint(val).build().getX509CertificateSha256Thumbprint()
    }


}
