package io.jsonwebtoken.impl.security

import io.jsonwebtoken.lang.Maps
import org.junit.Test
import static org.junit.Assert.*

class DefaultJwkBuilderTest {
    
    private static DefaultJwkBuilder builder() {
        return new DefaultJwkBuilder(Maps.of("typ", "okt").build())
    }


    @Test
    void testUse() {
        def val = UUID.randomUUID().toString()
        assertEquals val, builder().setUse(val).build().getUse()
    }

    @Test
    void testOperations() {
        def a = UUID.randomUUID().toString()
        def b = UUID.randomUUID().toString()
        def set = [a, b] as Set<String>
        assertEquals set, builder().setOperations(set).build().getOperations()
    }

    @Test
    void testAlgorithm() {
        def val = UUID.randomUUID().toString()
        assertEquals val, builder().setAlgorithm(val).build().getAlgorithm()
    }

    @Test
    void testId() {
        def val = UUID.randomUUID().toString()
        assertEquals val, builder().setId(val).build().getId()
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
