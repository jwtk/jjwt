package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.Bytes
import org.junit.Test

import java.security.cert.CertificateEncodingException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class JwtX509StringConverterTest {

    @Test
    void testApplyToThrowsEncodingException() {

        def ex = new CertificateEncodingException("foo")

        X509Certificate cert = createMock(X509Certificate)
        expect(cert.getEncoded()).andThrow(ex)
        replay cert

        try {
            JwtX509StringConverter.INSTANCE.applyTo(cert)
            fail()
        } catch (IllegalArgumentException expected) {
            String expectedMsg = 'Unable to access X509Certificate encoded bytes necessary to perform DER ' +
                    'Base64-encoding. Certificate: {EasyMock for class java.security.cert.X509Certificate}.  ' +
                    'Cause: ' + ex.getMessage()
            assertSame ex, expected.getCause()
            assertEquals expectedMsg, expected.getMessage()
        }

        verify cert
    }

    @Test
    void testApplyToWithEmptyEncoding() {

        X509Certificate cert = createMock(X509Certificate)
        expect(cert.getEncoded()).andReturn(Bytes.EMPTY)
        replay cert

        try {
            JwtX509StringConverter.INSTANCE.applyTo(cert)
            fail()
        } catch (IllegalArgumentException expected) {
            String expectedMsg = 'X509Certificate encoded bytes cannot be null or empty.  Certificate: ' +
                    '{EasyMock for class java.security.cert.X509Certificate}.'
            assertEquals expectedMsg, expected.getMessage()
        }

        verify cert
    }

    @Test
    void testApplyFromThrowsCertificateException() {

        def converter = new JwtX509StringConverter() {
            @Override
            protected CertificateFactory newCertificateFactory() throws CertificateException {
                throw new CertificateException("nope")
            }
        }

        String s = 'foo'
        try {
            converter.applyFrom(s)
            fail()
        } catch (IllegalArgumentException expected) {
            String expectedMsg = "Unable to convert Base64 String '$s' to X509Certificate instance. Cause: nope"
            assertEquals expectedMsg, expected.getMessage()
        }
    }
}
