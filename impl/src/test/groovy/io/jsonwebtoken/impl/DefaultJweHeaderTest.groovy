package io.jsonwebtoken.impl


import io.jsonwebtoken.impl.security.Randoms
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Collections
import io.jsonwebtoken.security.EcPrivateJwk
import io.jsonwebtoken.security.EcPublicJwk
import io.jsonwebtoken.security.Jwks
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

/**
 * @since JJWT_RELEASE_VERSION
 */
class DefaultJweHeaderTest {

    private DefaultJweHeader header

    @Before
    void setUp() {
        header = new DefaultJweHeader()
    }

    @Test
    void testAlgorithm() {
        header.setAlgorithm('foo')
        assertEquals 'foo', header.getAlgorithm()

        header = new DefaultJweHeader([alg: 'bar'])
        assertEquals 'bar', header.getAlgorithm()
    }

    @Test
    void testEncryptionAlgorithm() {
        header.put('enc', 'foo')
        assertEquals 'foo', header.getEncryptionAlgorithm()

        header = new DefaultJweHeader([enc: 'bar'])
        assertEquals 'bar', header.getEncryptionAlgorithm()
    }

    @Test
    void testJwkSetUrl() {
        URI uri = new URI('https://github.com/jwtk/jjwt')
        header.setJwkSetUrl(uri)
        assertEquals uri, header.getJwkSetUrl()
        assert uri.toString(), header.get('jku')
    }

    @Test
    void testJwk() {
        EcPrivateJwk jwk = Jwks.builder().setKeyPairEc(TestKeys.ES256.pair).build()
        EcPublicJwk pubJwk = jwk.toPublicJwk()
        header.setJwk(pubJwk)
        assertEquals pubJwk, header.getJwk()
    }

    @Test
    void testX509CertChain() {
        def bundle = TestKeys.RS256
        List<String> encodedCerts = Collections.of(Encoders.BASE64.encode(bundle.cert.getEncoded()))
        header.setX509CertificateChain(bundle.chain)
        assertEquals bundle.chain, header.getX509CertificateChain()
        assertEquals encodedCerts, header.get('x5c')
    }

    @Test
    void testX509CertSha1Thumbprint() {
        byte[] thumbprint = new byte[16] // simulate
        Randoms.secureRandom().nextBytes(thumbprint)
        String encoded = Encoders.BASE64URL.encode(thumbprint)
        header.setX509CertificateSha1Thumbprint(thumbprint)
        assertArrayEquals thumbprint, header.getX509CertificateSha1Thumbprint()
        assertEquals encoded, header.get('x5t')
    }

    @Test
    void testX509CertSha256Thumbprint() {
        byte[] thumbprint = new byte[32] // simulate
        Randoms.secureRandom().nextBytes(thumbprint)
        String encoded = Encoders.BASE64URL.encode(thumbprint)
        header.setX509CertificateSha256Thumbprint(thumbprint)
        assertArrayEquals thumbprint, header.getX509CertificateSha256Thumbprint()
        assertEquals encoded, header.get('x5t#S256')
    }

    @Test
    void testCritical() {
        Set<String> crits = Collections.setOf('foo', 'bar')
        header.setCritical(crits)
        assertEquals crits, header.getCritical()
    }
}
