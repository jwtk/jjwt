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
package io.jsonwebtoken.impl

import io.jsonwebtoken.impl.security.DefaultHashAlgorithm
import io.jsonwebtoken.impl.security.DefaultRequest
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.Request
import io.jsonwebtoken.security.StandardHashAlgorithms
import org.junit.Before
import org.junit.Test

import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.*

class DefaultJwsHeaderBuilderTest {

    DefaultJwsHeaderBuilder builder

    @Before
    void testSetUp() {
        builder = new DefaultJwsHeaderBuilder()
    }

    @Test
    void testNewHeader() {
        assertTrue builder.header instanceof DefaultJwsHeader
    }

    @Test
    void testSetJwkSetUrl() {
        URI uri = URI.create('https://github.com/jwtk/jjwt')
        assertEquals uri, builder.setJwkSetUrl(uri).build().getJwkSetUrl()
    }

    @Test
    void testSetJwk() {
        def jwk = Jwks.builder().forKey(TestKeys.RS256.pair.public as RSAPublicKey).build()
        assertEquals jwk, builder.setJwk(jwk).build().getJwk()
    }

    @Test
    void testSetKeyId() {
        assertEquals 'kid', builder.setKeyId('kid').build().getKeyId()
    }

    @Test
    void testSetX509Url() {
        URI uri = URI.create('https://github.com/jwtk/jjwt')
        assertEquals uri, builder.setX509Url(uri).build().getX509Url()
    }

    @Test
    void testSetX509CertificateChain() {
        def chain = TestKeys.RS256.chain
        assertEquals chain, builder.setX509CertificateChain(chain).build().getX509CertificateChain()
    }

    @Test
    void testSetX509CertificateSha1Thumbprint() {
        Request<byte[]> request = new DefaultRequest(TestKeys.RS256.cert.getEncoded(), null, null)
        def x5t = DefaultHashAlgorithm.SHA1.digest(request)
        String encoded = Encoders.BASE64URL.encode(x5t)
        def header = builder.setX509CertificateSha1Thumbprint(x5t).build()
        assertArrayEquals x5t, header.getX509CertificateSha1Thumbprint()
        assertEquals encoded, header.get('x5t')
    }

    @Test
    void testSetX509CertificateSha1ThumbprintEnabled() {
        def chain = TestKeys.RS256.chain
        Request<byte[]> request = new DefaultRequest(chain[0].getEncoded(), null, null)
        def x5t = DefaultHashAlgorithm.SHA1.digest(request)
        String encoded = Encoders.BASE64URL.encode(x5t)
        def header = builder.setX509CertificateChain(chain).withX509Sha1Thumbprint(true).build()
        assertArrayEquals x5t, header.getX509CertificateSha1Thumbprint()
        assertEquals encoded, header.get('x5t')
    }

    @Test
    void testSetX509CertificateSha256Thumbprint() {
        Request<byte[]> request = new DefaultRequest(TestKeys.RS256.cert.getEncoded(), null, null)
        def x5tS256 = StandardHashAlgorithms.get().SHA256.digest(request)
        String encoded = Encoders.BASE64URL.encode(x5tS256)
        def header = builder.setX509CertificateSha256Thumbprint(x5tS256).build()
        assertArrayEquals x5tS256, header.getX509CertificateSha256Thumbprint()
        assertEquals encoded, header.get('x5t#S256')
    }

    @Test
    void testSetX509CertificateSha256ThumbprintEnabled() {
        def chain = TestKeys.RS256.chain
        Request<byte[]> request = new DefaultRequest(chain[0].getEncoded(), null, null)
        def x5tS256 = StandardHashAlgorithms.get().SHA256.digest(request)
        String encoded = Encoders.BASE64URL.encode(x5tS256)
        def header = builder.setX509CertificateChain(chain).withX509Sha256Thumbprint(true).build()
        assertArrayEquals x5tS256, header.getX509CertificateSha256Thumbprint()
        assertEquals encoded, header.get('x5t#S256')
    }

    @Test
    void testSetCritical() {
        def crit = ['exp', 'sub'] as Set
        assertEquals crit, builder.setCritical(crit).build().getCritical()
    }
}
