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
