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
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.security.DefaultHashAlgorithm
import io.jsonwebtoken.impl.security.DefaultRequest
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.Request
import io.jsonwebtoken.security.StandardHashAlgorithms
import org.junit.Before
import org.junit.Test

import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.*

class DefaultJwtHeaderBuilderTest {

    static DefaultJwtHeaderBuilder builder
    static def header

    @Before
    void setUp() {
        header = null
        builder = Jwts.builder().header() as DefaultJwtHeaderBuilder
    }

    @SuppressWarnings('GroovyAssignabilityCheck')
    private static void assertSymmetry(String propName, def val) {
        def name = Strings.capitalize(propName)
        builder."set$name"(val)

        if (val instanceof byte[]) {
            assertArrayEquals val, builder."get$name"()
        } else {
            assertEquals val, builder."get$name"()
        }

        header = builder.build()
        if (val instanceof byte[]) {
            assertArrayEquals val, builder."get$name"()
        } else {
            assertEquals val, header."get$name"()
        }
    }

    private static void assertJws(String propName, def val) {
        assertSymmetry(propName, val)
        assertTrue header instanceof JwsHeader
        assertFalse header instanceof JweHeader
    }

    private static void assertJwe(String propName, def val) {
        assertSymmetry(propName, val)
        assertTrue header instanceof JweHeader
        assertFalse header instanceof JwsHeader
    }

    @Test
    void testDefault() { // no properties are set, so assert an unprotected header:
        header = builder.build()
        assertFalse header instanceof JwsHeader
        assertFalse header instanceof JweHeader
        assertTrue header instanceof DefaultHeader
    }

    // ====================== Map Methods =======================

    @Test
    void testSize() {
        assertEquals 0, builder.size()
        assertEquals 0, builder.build().size()

        builder.put('foo', 'bar')
        assertEquals 1, builder.size()
        assertEquals 1, builder.build().size()
    }

    @Test
    void testIsEmpty() {
        assertTrue builder.isEmpty()
        assertTrue builder.build().isEmpty()

        builder.put('foo', 'bar')
        assertFalse builder.isEmpty()
        assertFalse builder.build().isEmpty()
    }

    @Test
    void testContainsKey() {
        def key = 'foo'
        assertFalse builder.containsKey(key)
        assertFalse builder.build().containsKey(key)

        builder.put(key, 'bar')
        assertTrue builder.containsKey(key)
        assertTrue builder.build().containsKey(key)
    }

    @Test
    void testContainsValue() {
        def value = 'bar'
        assertFalse builder.containsValue(value)
        assertFalse builder.build().containsValue(value)

        builder.put('foo', value)
        assertTrue builder.containsValue(value)
        assertTrue builder.build().containsValue(value)
    }

    @Test
    void testGet() {
        def key = 'foo'
        def value = 'bar'
        assertNull builder.get(key)
        assertNull builder.build().get(key)

        builder.put(key, value)
        assertEquals value, builder.get(key)
        assertEquals value, builder.build().get(key)
    }

    @Test
    void testKeySet() {
        def key = 'foo'
        def value = 'bar'
        assertTrue builder.keySet().isEmpty()
        assertTrue builder.build().keySet().isEmpty()

        builder.put(key, value)
        assertFalse builder.keySet().isEmpty()
        assertFalse builder.build().keySet().isEmpty()
        assertEquals 1, builder.keySet().size()
        assertEquals 1, builder.build().keySet().size()
        assertEquals key, builder.keySet().iterator().next()
        assertEquals key, builder.build().keySet().iterator().next()

        def i = builder.keySet().iterator()
        i.next()
        i.remove() // assert keyset modification modifies builder state:
        assertTrue builder.keySet().isEmpty()
        assertTrue builder.build().keySet().isEmpty()
    }

    @Test
    void testValues() {
        def key = 'foo'
        def value = 'bar'
        assertTrue builder.values().isEmpty()
        assertTrue builder.build().values().isEmpty()

        builder.put(key, value)
        assertFalse builder.values().isEmpty()
        assertFalse builder.build().values().isEmpty()
        assertEquals 1, builder.values().size()
        assertEquals 1, builder.build().values().size()
        assertEquals value, builder.values().iterator().next()
        assertEquals value, builder.build().values().iterator().next()

        def i = builder.values().iterator()
        i.next()
        i.remove() // assert values modification modifies builder state:
        assertTrue builder.values().isEmpty()
        assertTrue builder.build().values().isEmpty()
    }

    @Test
    void testEntrySet() {
        def key = 'foo'
        def value = 'bar'
        assertTrue builder.entrySet().isEmpty()
        assertTrue builder.build().entrySet().isEmpty()

        builder.put(key, value)
        assertFalse builder.entrySet().isEmpty()
        assertFalse builder.build().entrySet().isEmpty()
        assertEquals 1, builder.entrySet().size()
        assertEquals 1, builder.build().entrySet().size()
        def entry = builder.entrySet().iterator().next()
        assertEquals key, entry.getKey()
        assertEquals value, entry.getValue()

        def i = builder.entrySet().iterator()
        i.next()
        i.remove() // assert values modification modifies builder state:
        assertTrue builder.entrySet().isEmpty()
        assertTrue builder.build().entrySet().isEmpty()
    }

    @Test
    void testPut() {
        builder.put('foo', 'bar')
        assertEquals 'bar', builder.get('foo')
        assertEquals 'bar', builder.build().get('foo')
    }

    @Test
    void testPutAll() {
        def m = ['foo': 'bar', 'baz': 'bat']
        def header = builder.putAll(m).build()
        assertEquals m, header
    }

    @Test
    void testRemove() {
        builder.put('foo', 'bar').remove('foo')
        assertTrue builder.isEmpty()
        assertTrue builder.build().isEmpty()
    }

    @Test
    void testClear() {
        def m = ['foo': 'bar', 'baz': 'bat']
        def header = builder.putAll(m).clear().build()
        assertTrue header.isEmpty()
    }

    // ====================== Generic Header Methods =======================

    @Test
    void testType() {
        assertSymmetry('type', 'foo')
    }

    @Test
    void testContentType() {
        assertSymmetry('contentType', 'text/plain')
    }

    /**
     * Asserts that if the 'alg' member is set to any other value other than 'none', but no JWE-only members
     * are set, a JwsHeader is created.  Although a JweHeader also has an 'alg' value, there must be at least
     * one JWE-only member set as well to trigger JweHeader creation.
     */
    @Test
    void testAlgNone() { // alg of 'none', so build an unprotected header:
        assertSymmetry('algorithm', 'none')
        assertFalse header instanceof JwsHeader
        assertFalse header instanceof JweHeader
        assertTrue header instanceof DefaultHeader
    }

    @Test
    void testCompressionAlgorithm() {
        assertSymmetry('compressionAlgorithm', 'DEF')
    }

    // ====================== Protected Header Methods =======================

    /**
     * Asserts that if the protected-header-only 'jku' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testJwkSetUrl() {
        URI uri = URI.create('https://github.com/jwtk/jjwt')
        assertJws('jwkSetUrl', uri)
    }

    /**
     * Asserts that if the protected-header-only 'jwk' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testJwk() {
        def jwk = Jwks.builder().forKey(TestKeys.RS256.pair.public as RSAPublicKey).build()
        assertJws('jwk', jwk)
    }

    /**
     * Asserts that if the protected-header-only 'kid' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testKeyId() {
        assertJws('keyId', 'hello')
    }

    /**
     * Asserts that if the protected-header-only 'crit' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testCritical() {
        def crit = ['exp', 'sub'] as Set<String>
        assertJws('critical', crit)
    }

    // ====================== X.509 Methods =======================

    /**
     * Asserts that if the protected-header-only 'x5u' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testX09Url() {
        def uri = URI.create('https://github.com/jwtk/jjwt')
        assertJws('x509Url', uri)
    }

    /**
     * Asserts that if the protected-header-only 'x5c' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testX509CertificateChain() {
        def chain = TestKeys.RS256.chain
        assertJws('x509CertificateChain', chain)
    }

    /**
     * Asserts that if the protected-header-only 'x5t' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testX509CertificateSha1Thumbprint() {
        Request<byte[]> request = new DefaultRequest(TestKeys.RS256.cert.getEncoded(), null, null)
        def x5t = DefaultHashAlgorithm.SHA1.digest(request)
        String encoded = Encoders.BASE64URL.encode(x5t)

        builder.setX509CertificateSha1Thumbprint(x5t)
        assertArrayEquals x5t, builder.getX509CertificateSha1Thumbprint()
        assertEquals encoded, builder.get('x5t')

        header = builder.build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertArrayEquals x5t, header.getX509CertificateSha1Thumbprint()
        assertEquals encoded, header.get('x5t')
    }

    @Test
    void testX509CertificateSha1ThumbprintEnabled() {
        def chain = TestKeys.RS256.chain
        Request<byte[]> request = new DefaultRequest(chain[0].getEncoded(), null, null)
        def x5t = DefaultHashAlgorithm.SHA1.digest(request)
        String encoded = Encoders.BASE64URL.encode(x5t)
        def header = builder.setX509CertificateChain(chain).withX509Sha1Thumbprint(true).build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertArrayEquals x5t, header.getX509CertificateSha1Thumbprint()
        assertEquals encoded, header.get('x5t')
    }

    /**
     * Asserts that if the protected-header-only 'x5t#S256' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testX509CertificateSha256Thumbprint() {
        Request<byte[]> request = new DefaultRequest(TestKeys.RS256.cert.getEncoded(), null, null)
        def x5tS256 = Jwks.HASH.SHA256.digest(request)
        String encoded = Encoders.BASE64URL.encode(x5tS256)

        builder.setX509CertificateSha256Thumbprint(x5tS256)
        assertArrayEquals x5tS256, builder.getX509CertificateSha256Thumbprint()
        assertEquals encoded, builder.get('x5t#S256')

        header = builder.build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertArrayEquals x5tS256, header.getX509CertificateSha256Thumbprint()
        assertEquals encoded, header.get('x5t#S256')
    }

    @Test
    void testX509CertificateSha256ThumbprintEnabled() {
        def chain = TestKeys.RS256.chain
        Request<byte[]> request = new DefaultRequest(chain[0].getEncoded(), null, null)
        def x5tS256 = StandardHashAlgorithms.get().SHA256.digest(request)
        String encoded = Encoders.BASE64URL.encode(x5tS256)
        def header = builder.setX509CertificateChain(chain).withX509Sha256Thumbprint(true).build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertArrayEquals x5tS256, header.getX509CertificateSha256Thumbprint()
        assertEquals encoded, header.get('x5t#S256')
    }

    // ====================== JWE Header Methods =======================

    @Test
    void testEncryptionAlgorithm() {
        def enc = Jwts.ENC.A256GCM.getId()
        builder.put('enc', enc)
        assertEquals enc, builder.getEncryptionAlgorithm()

        header = builder.build() as JweHeader
        assertEquals enc, header.getEncryptionAlgorithm()
    }

    @Test
    void testEphemeralPublicKey() {
        def key = TestKeys.ES256.pair.public
        def jwk = Jwks.builder().forKey(key).build()

        builder.put('epk', jwk)
        assertEquals jwk, builder.getEphemeralPublicKey()

        header = builder.build() as JweHeader
        assertEquals jwk, header.getEphemeralPublicKey()
    }

    @Test
    void testAgreementPartyUInfo() {
        def info = Strings.utf8("UInfo")
        assertJwe('agreementPartyUInfo', info)
    }

    @Test
    void testAgreementPartyUInfoString() {
        def s = "UInfo"
        def info = Strings.utf8(s)
        builder.setAgreementPartyUInfo(s).build()
        assertArrayEquals info, builder.getAgreementPartyUInfo()

        header = builder.build() as JweHeader
        assertArrayEquals info, header.getAgreementPartyUInfo()
    }

    @Test
    void testAgreementPartyVInfo() {
        def info = Strings.utf8("VInfo")
        assertJwe('agreementPartyVInfo', info)
    }

    @Test
    void testAgreementPartyVInfoString() {
        def s = "VInfo"
        def info = Strings.utf8(s)
        builder.setAgreementPartyVInfo(s)
        assertArrayEquals info, builder.getAgreementPartyVInfo()

        header = builder.build() as JweHeader
        assertArrayEquals info, header.getAgreementPartyVInfo()
    }

    @Test
    void testPbes2Salt() {
        byte[] salt = Bytes.randomBits(256)
        builder.put('p2s', salt)
        assertArrayEquals salt, builder.getPbes2Salt()

        header = builder.build() as JweHeader
        assertArrayEquals salt, header.getPbes2Salt()
    }

    @Test
    void testPbes2Count() {
        int count = 4096
        assertJwe('pbes2Count', count)
    }

    @Test
    void testInitializationVector() {
        byte[] val = Bytes.randomBits(96)
        builder.put('iv', val)
        assertArrayEquals val, builder.getInitializationVector()

        header = builder.build() as JweHeader
        assertArrayEquals val, header.getInitializationVector()
    }

    @Test
    void testAuthenticationTag() {
        byte[] val = Bytes.randomBits(128)
        builder.put('tag', val)
        assertArrayEquals val, builder.getAuthenticationTag()

        header = builder.build() as JweHeader
        assertArrayEquals val, header.getAuthenticationTag()
    }

    @Test
    void testUnprotectedHeaderChangedToProtectedHeaderChangedToJweHeader() {
        builder.put('foo', 'bar')
        assertEquals new DefaultHeader([foo: 'bar']), builder.build()

        // add JWS-required property:
        builder.setAlgorithm('HS256')
        assertEquals new DefaultJwsHeader([foo: 'bar', alg: 'HS256']), builder.build()

        // add JWE required property:
        builder.put(DefaultJweHeader.ENCRYPTION_ALGORITHM.getId(), Jwts.ENC.A256GCM.getId())
        assertEquals new DefaultJweHeader([foo: 'bar', alg: 'HS256', enc: 'A256GCM']), builder.build()
    }
}