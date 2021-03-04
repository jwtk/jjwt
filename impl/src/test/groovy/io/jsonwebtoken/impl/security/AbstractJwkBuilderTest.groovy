package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.Jwk
import org.junit.Test
import static org.junit.Assert.*

class AbstractJwkBuilderTest {

    static final JwkValidator TEST_VALIDATOR = new TestJwkValidator()

    class TestJwkBuilder extends AbstractJwkBuilder {
        def TestJwkBuilder(JwkValidator validator=TEST_VALIDATOR) {
            super(validator)
        }
        @Override
        def Jwk newJwk() {
            return new TestJwk()
        }
    }

    class NullJwkBuilder extends AbstractJwkBuilder {
        def NullJwkBuilder(JwkValidator validator=TEST_VALIDATOR) {
            super(validator)
        }
        @Override
        def Jwk newJwk() {
            return null
        }
    }

    @Test(expected = IllegalArgumentException)
    void testCtorWithNullValidator() {
        new TestJwkBuilder(null)
    }

    @Test
    void testCtorNonNullNewJwk() {
        def builder = new TestJwkBuilder()
        assertTrue builder.jwk instanceof TestJwk
    }

    @Test(expected=IllegalArgumentException)
    void testCtorWithSubclassNullJwk() {
        new NullJwkBuilder()
    }

    @Test
    void testUse() {
        def val = UUID.randomUUID().toString()
        assertEquals val, new TestJwkBuilder().setUse(val).build().getUse()
    }

    @Test
    void testOperations() {
        def a = UUID.randomUUID().toString()
        def b = UUID.randomUUID().toString()
        def set = [a, b] as Set<String>
        assertEquals set, new TestJwkBuilder().setOperations(set).build().getOperations()
    }

    @Test
    void testAlgorithm() {
        def val = UUID.randomUUID().toString()
        assertEquals val, new TestJwkBuilder().setAlgorithm(val).build().getAlgorithm()
    }

    @Test
    void testId() {
        def val = UUID.randomUUID().toString()
        assertEquals val, new TestJwkBuilder().setId(val).build().getId()
    }

    @Test
    void testX509Url() {
        def val = new URI(UUID.randomUUID().toString())
        assertEquals val, new TestJwkBuilder().setX509Url(val).build().getX509Url()
    }

    @Test
    void testX509CertificateChain() {
        def a = UUID.randomUUID().toString()
        def b = UUID.randomUUID().toString()
        def val = [a, b] as List<String>
        assertEquals val, new TestJwkBuilder().setX509CertificateChain(val).build().getX509CertficateChain()
    }

    @Test
    void testX509CertificateSha1Thumbprint() {
        def val = UUID.randomUUID().toString()
        assertEquals val, new TestJwkBuilder().setX509CertificateSha1Thumbprint(val).build().getX509CertificateSha1Thumbprint()
    }

    @Test
    void testX509CertificateSha256Thumbprint() {
        def val = UUID.randomUUID().toString()
        assertEquals val, new TestJwkBuilder().setX509CertificateSha256Thumbprint(val).build().getX509CertificateSha256Thumbprint()
    }
}
