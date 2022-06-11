/*
 * Copyright (C) 2021 jsonwebtoken.io
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

import io.jsonwebtoken.JweHeader
import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.UnprotectedHeader
import io.jsonwebtoken.impl.security.ContentRequest
import io.jsonwebtoken.impl.security.DefaultContentRequest
import io.jsonwebtoken.impl.security.DefaultHashAlgorithm
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.Jwks
import org.junit.Before
import org.junit.Test

import java.nio.charset.StandardCharsets
import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.*

class DefaultDynamicHeaderBuilderTest {

    static DefaultDynamicHeaderBuilder builder

    @Before
    void setUp() {
        builder = Jwts.headerBuilder() as DefaultDynamicHeaderBuilder
    }

    @Test
    void testType() {
        String type = 'foo'
        def header = builder.setType(type).build()
        assertTrue header instanceof UnprotectedHeader
        assertEquals type, header.getType()
    }

    @Test
    void testContentType() {
        String cty = 'text/plain'
        def header = builder.setContentType(cty).build()
        assertTrue header instanceof UnprotectedHeader
        assertEquals cty, header.getContentType()
    }

    @Test
    void testAlgorithm() {
        String alg = 'none'
        def header = builder.setAlgorithm(alg).build()
        assertTrue header instanceof UnprotectedHeader
        assertEquals alg, header.getAlgorithm()
    }

    @Test
    void testCompressionAlgorithm() {
        String zip = 'DEF'
        def header = builder.setCompressionAlgorithm(zip).build()
        assertTrue header instanceof UnprotectedHeader
        assertEquals zip, header.getCompressionAlgorithm()
    }

    @Test
    void testPut() {
        def header = builder.put('foo', 'bar').build()
        assertTrue header instanceof UnprotectedHeader
        assertEquals 'bar', header.get('foo')
    }

    @Test
    void testPutAll() {
        def m = ['foo': 'bar', 'baz': 'bat']
        def header = builder.putAll(m).build()
        assertTrue header instanceof UnprotectedHeader
        assertEquals m, header
    }

    @Test
    void testRemove() {
        def header = builder.put('foo', 'bar').remove('foo').build()
        assertTrue header instanceof UnprotectedHeader
        assertTrue header.isEmpty()
    }

    @Test
    void testClear() {
        def m = ['foo': 'bar', 'baz': 'bat']
        def header = builder.putAll(m).clear().build()
        assertTrue header instanceof UnprotectedHeader
        assertTrue header.isEmpty()
    }

    @Test
    void testSetJwkSetUrl() {
        URI uri = URI.create('https://github.com/jwtk/jjwt')
        def header = builder.setJwkSetUrl(uri).build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertEquals uri, header.getJwkSetUrl()
    }

    @Test
    void testSetJwk() {
        def jwk = Jwks.builder().forKey(TestKeys.RS256.pair.public as RSAPublicKey).build()
        def header = builder.setJwk(jwk).build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertEquals jwk, header.getJwk()
    }

    @Test
    void testSetKeyId() {
        def header = builder.setKeyId('kid').build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertEquals 'kid', header.getKeyId()
    }

    @Test
    void testSetX509Url() {
        URI uri = URI.create('https://github.com/jwtk/jjwt')
        def header = builder.setX509Url(uri).build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertEquals uri, header.getX509Url()
    }

    @Test
    void testSetX509CertificateChain() {
        def chain = TestKeys.RS256.chain
        def header = builder.setX509CertificateChain(chain).build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertEquals chain, header.getX509CertificateChain()
    }

    @Test
    void testSetX509CertificateSha1Thumbprint() {
        ContentRequest request = new DefaultContentRequest(null, null, TestKeys.RS256.cert.getEncoded())
        def x5t = DefaultHashAlgorithm.SHA1.hash(request)
        String encoded = Encoders.BASE64URL.encode(x5t)
        def header = builder.setX509CertificateSha1Thumbprint(x5t).build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertArrayEquals x5t, header.getX509CertificateSha1Thumbprint()
        assertEquals encoded, header.get('x5t')
    }

    @Test
    void testSetX509CertificateSha1ThumbprintEnabled() {
        def chain = TestKeys.RS256.chain
        ContentRequest request = new DefaultContentRequest(null, null, chain[0].getEncoded())
        def x5t = DefaultHashAlgorithm.SHA1.hash(request)
        String encoded = Encoders.BASE64URL.encode(x5t)
        def header = builder.setX509CertificateChain(chain).withX509Sha1Thumbprint(true).build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertArrayEquals x5t, header.getX509CertificateSha1Thumbprint()
        assertEquals encoded, header.get('x5t')
    }

    @Test
    void testSetX509CertificateSha256Thumbprint() {
        ContentRequest request = new DefaultContentRequest(null, null, TestKeys.RS256.cert.getEncoded())
        def x5tS256 = DefaultHashAlgorithm.SHA256.hash(request)
        String encoded = Encoders.BASE64URL.encode(x5tS256)
        def header = builder.setX509CertificateSha256Thumbprint(x5tS256).build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertArrayEquals x5tS256, header.getX509CertificateSha256Thumbprint()
        assertEquals encoded, header.get('x5t#S256')
    }

    @Test
    void testSetX509CertificateSha256ThumbprintEnabled() {
        def chain = TestKeys.RS256.chain
        ContentRequest request = new DefaultContentRequest(null, null, chain[0].getEncoded())
        def x5tS256 = DefaultHashAlgorithm.SHA256.hash(request)
        String encoded = Encoders.BASE64URL.encode(x5tS256)
        def header = builder.setX509CertificateChain(chain).withX509Sha256Thumbprint(true).build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertArrayEquals x5tS256, header.getX509CertificateSha256Thumbprint()
        assertEquals encoded, header.get('x5t#S256')
    }

    @Test
    void testSetCritical() {
        def crit = ['exp', 'sub'] as Set
        def header = builder.setCritical(crit).build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertEquals crit, header.getCritical()
    }

    @Test
    void testSetAgreementPartyUInfo() {
        def info = "UInfo".getBytes(StandardCharsets.UTF_8)
        def header = builder.setAgreementPartyUInfo(info).build() as JweHeader
        assertTrue header instanceof JweHeader
        assertArrayEquals info, header.getAgreementPartyUInfo()
    }

    @Test
    void testSetAgreementPartyUInfoString() {
        def s = "UInfo"
        def info = s.getBytes(StandardCharsets.UTF_8)
        def header = builder.setAgreementPartyUInfo(s).build() as JweHeader
        assertTrue header instanceof JweHeader
        assertArrayEquals info, header.getAgreementPartyUInfo()
    }

    @Test
    void testSetAgreementPartyVInfo() {
        def info = "VInfo".getBytes(StandardCharsets.UTF_8)
        def header = builder.setAgreementPartyVInfo(info).build() as JweHeader
        assertTrue header instanceof JweHeader
        assertArrayEquals info, header.getAgreementPartyVInfo()
    }

    @Test
    void testSetAgreementPartyVInfoString() {
        def s = "VInfo"
        def info = s.getBytes(StandardCharsets.UTF_8)
        def header = builder.setAgreementPartyVInfo(s).build() as JweHeader
        assertTrue header instanceof JweHeader
        assertArrayEquals info, header.getAgreementPartyVInfo()
    }

    @Test
    void testSetPbes2Count() {
        int count = 4096
        def header = builder.setPbes2Count(count).build() as JweHeader
        assertTrue header instanceof JweHeader
        assertEquals count, header.getPbes2Count()
    }

    @Test
    void testUnprotectedHeaderChangedToProtectedHeaderChangedToJweHeader() {
        def header = builder.put('foo', 'bar') // all headers
                .setKeyId('baz') // protected header properties
                .setPbes2Count(2048).setAgreementPartyUInfo("info").build() as JweHeader // JWE properties
        assertTrue header instanceof JweHeader
        def encoded = Encoders.BASE64URL.encode('info'.getBytes(StandardCharsets.UTF_8))
        def expected = new DefaultJweHeader(['foo': 'bar', 'kid': 'baz', 'p2c': 2048, 'apu': encoded])
        assertEquals expected, header
    }
}
