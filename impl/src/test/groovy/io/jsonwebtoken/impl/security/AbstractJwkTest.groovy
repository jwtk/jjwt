package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test
import static org.junit.Assert.*

class AbstractJwkTest {

    class TestJwk<T extends Jwk> extends AbstractJwk<Jwk> {
        TestJwk() {
            super("test")
        }
    }

    class NullTypeJwk extends AbstractJwk {
        NullTypeJwk() {
            super(null)
        }
    }

    class EmptyTypeJwk extends AbstractJwk {
        EmptyTypeJwk() {
            super("  ")
        }
    }

    @Test(expected=IllegalArgumentException)
    void testNullType() {
        new NullTypeJwk()
    }

    @Test(expected=IllegalArgumentException)
    void testEmptyType() {
        new EmptyTypeJwk()
    }

    @Test
    void testType() {
        assertEquals "test", new TestJwk().getType()
    }

    @Test
    void testUse() {
        def jwk = new TestJwk()

        assertEquals 'use', AbstractJwk.USE

        jwk.setUse(null)
        assertNull jwk.get(AbstractJwk.USE)
        assertNull jwk.getUse()

        jwk.setUse('  ') //empty should remove
        assertNull jwk.get(AbstractJwk.USE)
        assertNull jwk.getUse()

        String val = UUID.randomUUID().toString()

        jwk.setUse(val)
        assertEquals val, jwk.get(AbstractJwk.USE)
        assertEquals val, jwk.getUse()
    }

    @Test
    void testOperations() {

        def jwk = new TestJwk()

        assertEquals 'key_ops', AbstractJwk.OPERATIONS

        jwk.setOperations(null)
        assertNull jwk.get(AbstractJwk.OPERATIONS)
        assertNull jwk.getOperations()

        jwk.setOperations([] as Set<String>) //empty should remove
        assertNull jwk.get(AbstractJwk.OPERATIONS)
        assertNull jwk.getOperations()

        def set = ['a', 'b'] as Set<String>

        jwk.setOperations(set)
        assertEquals set, jwk.get(AbstractJwk.OPERATIONS)
        assertEquals set, jwk.getOperations()
    }

    @Test
    void testAlgorithm() {
        def jwk = new TestJwk()

        assertEquals 'alg', AbstractJwk.ALGORITHM

        jwk.setAlgorithm(null)
        assertNull jwk.get(AbstractJwk.ALGORITHM)
        assertNull jwk.getAlgorithm()

        jwk.setAlgorithm('  ') //empty should remove
        assertNull jwk.get(AbstractJwk.ALGORITHM)
        assertNull jwk.getAlgorithm()

        String val = UUID.randomUUID().toString()
        jwk.setAlgorithm(val)
        assertEquals val, jwk.get(AbstractJwk.ALGORITHM)
        assertEquals val, jwk.getAlgorithm()
    }

    @Test
    void testId() {
        def jwk = new TestJwk()

        assertEquals 'kid', AbstractJwk.ID

        jwk.setId(null)
        assertNull jwk.get(AbstractJwk.ID)
        assertNull jwk.getId()

        jwk.setId('  ') //empty should remove
        assertNull jwk.get(AbstractJwk.ID)
        assertNull jwk.getId()

        String val = UUID.randomUUID().toString()
        jwk.setId(val)
        assertEquals val, jwk.get(AbstractJwk.ID)
        assertEquals val, jwk.getId()
    }

    @Test
    void testX509Sha1Thumbprint() {
        def jwk = new TestJwk()

        assertEquals 'x5t', AbstractJwk.X509_SHA1_THUMBPRINT

        jwk.setX509CertificateSha1Thumbprint(null)
        assertNull jwk.get(AbstractJwk.X509_SHA1_THUMBPRINT)
        assertNull jwk.getX509CertificateSha1Thumbprint()

        jwk.setX509CertificateSha1Thumbprint('  ') //empty should remove
        assertNull jwk.get(AbstractJwk.X509_SHA1_THUMBPRINT)
        assertNull jwk.getX509CertificateSha1Thumbprint()

        String val = UUID.randomUUID().toString()
        jwk.setX509CertificateSha1Thumbprint(val)
        assertEquals val, jwk.get(AbstractJwk.X509_SHA1_THUMBPRINT)
        assertEquals val, jwk.getX509CertificateSha1Thumbprint()
    }

    @Test
    void testX509Sha256Thumbprint() {
        def jwk = new TestJwk()

        assertEquals 'x5t#S256', AbstractJwk.X509_SHA256_THUMBPRINT

        jwk.setX509CertificateSha1Thumbprint(null)
        assertNull jwk.get(AbstractJwk.X509_SHA256_THUMBPRINT)
        assertNull jwk.getX509CertificateSha256Thumbprint()

        jwk.setX509CertificateSha256Thumbprint('  ') //empty should remove
        assertNull jwk.get(AbstractJwk.X509_SHA256_THUMBPRINT)
        assertNull jwk.getX509CertificateSha256Thumbprint()

        String val = UUID.randomUUID().toString()
        jwk.setX509CertificateSha256Thumbprint(val)
        assertEquals val, jwk.get(AbstractJwk.X509_SHA256_THUMBPRINT)
        assertEquals val, jwk.getX509CertificateSha256Thumbprint()
    }

    @Test
    void testX509Url() {

        def jwk = new TestJwk()

        assertEquals 'x5u', AbstractJwk.X509_URL

        jwk.setX509Url(null)
        assertNull jwk.get(AbstractJwk.X509_URL)
        assertNull jwk.getX509Url()

        String suri = 'https://whatever.com/cert'
        def uri = new URI(suri)

        jwk.put(AbstractJwk.X509_URL, uri)
        assertEquals uri, jwk.get(AbstractJwk.X509_URL)
        assertEquals uri, jwk.getX509Url()

        jwk.put(AbstractJwk.X509_URL, suri)
        assertEquals suri, jwk.get(AbstractJwk.X509_URL) //string here
        assertEquals uri, jwk.getX509Url() //conversion here
        assertEquals uri, jwk.get(AbstractJwk.X509_URL) //ensure replaced with URI instance

        jwk.remove(AbstractJwk.X509_URL) //clear for next test

        jwk.setX509Url(uri)
        assertEquals uri, jwk.get(AbstractJwk.X509_URL)
        assertEquals uri, jwk.getX509Url()
    }

    @Test
    void testGetX509UrlWithInvalidUri() {
        def jwk = new TestJwk()
        def uri = '|not-a-uri|'
        jwk.put(AbstractJwk.X509_URL, uri)
        try {
            jwk.getX509Url()
            fail()
        } catch (MalformedKeyException e) {
            assertEquals 'test JWK x5u value cannot be converted to a URI instance: ' + uri, e.getMessage()
            assertTrue e.getCause() instanceof URISyntaxException
        }
    }

    @Test
    void testGetListWithNullValue() {
        assertNull new TestJwk().getList("foo")
    }

    @Test
    void testGetX509CertChainWithSet() {
        def jwk = new TestJwk()
        jwk.put('x5c', new LinkedHashSet<>(['a', null, 'b']))
        def chain = jwk.getX509CertficateChain()
        assertTrue chain instanceof List
        assertEquals 3, chain.size()
        assertEquals 'a', chain[0]
        assertNull chain[1]
        assertEquals 'b', chain[2]
    }

    @Test
    void testGetX509CertChainWithArray() {
        def jwk = new TestJwk()
        jwk.put('x5c', ['a', null, 'b'] as String[])
        def chain = jwk.getX509CertficateChain()
        assertTrue chain instanceof List
        assertEquals 3, chain.size()
        assertEquals 'a', chain[0]
        assertNull chain[1]
        assertEquals 'b', chain[2]
    }

    @Test
    void testSetX509CertChain() {

        def jwk = new TestJwk()

        assertEquals 'x5c', AbstractJwk.X509_CERT_CHAIN

        jwk.setX509CertificateChain(null)
        assertNull jwk.get(AbstractJwk.X509_CERT_CHAIN)
        assertNull jwk.getX509CertficateChain()

        jwk.setX509CertificateChain([])
        assertNull jwk.get(AbstractJwk.X509_CERT_CHAIN)
        assertNull jwk.getX509CertficateChain()

        String val = UUID.randomUUID().toString()
        def chain = [val]
        jwk.setX509CertificateChain(chain)
        assertEquals chain, jwk.get(AbstractJwk.X509_CERT_CHAIN)
        assertEquals chain, jwk.getX509CertficateChain()
    }
}
