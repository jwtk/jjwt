/*
 * Copyright (C) 2022 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.SecurityException
import org.junit.Before
import org.junit.Test

import java.security.Provider
import java.security.cert.CertificateEncodingException
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class JwtX509StringConverterTest {

    private JwtX509StringConverter converter

    @Before
    void setUp() {
        converter = JwtX509StringConverter.INSTANCE
    }

    @Test
    void testApplyToThrowsEncodingException() {

        def ex = new CertificateEncodingException("foo")

        X509Certificate cert = createMock(X509Certificate)
        expect(cert.getEncoded()).andThrow(ex)
        replay cert

        try {
            converter.applyTo(cert)
            fail()
        } catch (IllegalArgumentException expected) {
            String expectedMsg = "Unable to access X509Certificate encoded bytes necessary to perform DER " +
                    "Base64-encoding. Certificate: {${cert}}. Cause: " + ex.getMessage()
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
            converter.applyTo(cert)
            fail()
        } catch (IllegalArgumentException expected) {
            String expectedMsg = 'X509Certificate encoded bytes cannot be null or empty.  Certificate: ' +
                    '{EasyMock for class java.security.cert.X509Certificate}.'
            assertEquals expectedMsg, expected.getMessage()
        }

        verify cert
    }

    @Test
    void testApplyFromBadBase64() {
        final CertificateException ex = new CertificateException('nope')
        converter = new JwtX509StringConverter() {
            @Override
            protected X509Certificate toCert(byte[] der, Provider provider) throws SecurityException {
                assertNull provider // ensures not called twice (no fallback) because der bytes aren't available
                throw ex
            }
        }

        String s = 'foo'
        try {
            converter.applyFrom(s)
            fail()
        } catch (IllegalArgumentException expected) {
            String expectedMsg = "Unable to convert Base64 String '$s' to X509Certificate instance. Cause: nope"
            assertEquals expectedMsg, expected.getMessage()
            assertSame ex, expected.getCause()
        }
    }

    @Test
    void testApplyFromRsaSsaPssCertStringWithSuccessfulBCRetry() {
        final CertificateException ex = new CertificateException("nope: ${RsaSignatureAlgorithm.PSS_OID}")
        converter = new JwtX509StringConverter() {
            @Override
            protected X509Certificate toCert(byte[] der, Provider provider) throws SecurityException {
                if (provider == null) {
                    throw ex // first time called, throw ex (simulates JVM parse failure)
                } else { // this time BC is available:
                    assertNotNull provider
                    return super.toCert(der, provider)
                }
            }
        }

        def cert = TestKeys.RS256.cert
        def validBase64 = Encoders.BASE64.encode(cert.getEncoded())
        assertEquals cert, converter.applyFrom(validBase64)
    }

    @Test
    void testApplyFromRsaSsaPssCertStringWithFailedBCRetry() {
        final String exMsg = "nope: ${RsaSignatureAlgorithm.PSS_OID}"
        final CertificateException ex = new CertificateException(exMsg)
        converter = new JwtX509StringConverter() {
            @Override
            protected X509Certificate toCert(byte[] der, Provider provider) throws SecurityException {
                throw ex // ensure fails first and second time
            }
        }

        def cert = TestKeys.RS256.cert
        def validBase64 = Encoders.BASE64.encode(cert.getEncoded())

        try {
            converter.applyFrom(validBase64)
            fail()
        } catch (IllegalArgumentException expected) {
            String expectedMsg = "Unable to convert Base64 String '$validBase64' to X509Certificate instance. Cause: ${exMsg}"
            assertEquals expectedMsg, expected.getMessage()
            assertSame ex, expected.getCause()
        }
    }
}
