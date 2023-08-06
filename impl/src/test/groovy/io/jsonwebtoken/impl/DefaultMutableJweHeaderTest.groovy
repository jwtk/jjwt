/*
 * Copyright © 2023 jsonwebtoken.io
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

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.security.DefaultHashAlgorithm
import io.jsonwebtoken.impl.security.DefaultRequest
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.Request
import org.junit.Before
import org.junit.Test

import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.*

class DefaultMutableJweHeaderTest {

    static DefaultMutableJweHeader header

    @Before
    void setUp() {
        header = new DefaultMutableJweHeader(Jwts.header() as DefaultJweHeaderMutator)
    }

    @SuppressWarnings('GroovyAssignabilityCheck')
    private static void assertSymmetry(String propName, def val) {
        def name = Strings.capitalize(propName)
        switch (propName) {
            case 'algorithm': header.add('alg', val); break // no setter
            case 'compressionAlgorithm': header.add('zip', val); break // no setter
            default: header."$propName"(val)
        }

        if (val instanceof byte[]) {
            assertArrayEquals val, header."get$name"()
        } else {
            assertEquals val, header."get$name"()
        }
    }

    // ====================== Map Methods =======================

    @Test
    void testSize() {
        assertEquals 0, header.size()
        header.put('foo', 'bar')
        assertEquals 1, header.size()
    }

    @Test
    void testIsEmpty() {
        assertTrue header.isEmpty()
        header.put('foo', 'bar')
        assertFalse header.isEmpty()
    }

    @Test
    void testContainsKey() {
        def key = 'foo'
        assertFalse header.containsKey(key)
        header.put(key, 'bar')
        assertTrue header.containsKey(key)
    }

    @Test
    void testContainsValue() {
        def value = 'bar'
        assertFalse header.containsValue(value)
        header.put('foo', value)
        assertTrue header.containsValue(value)
    }

    @Test
    void testGet() {
        def key = 'foo'
        def value = 'bar'
        assertNull header.get(key)
        header.put(key, value)
        assertEquals value, header.get(key)
    }

    @Test
    void testKeySet() {
        def key = 'foo'
        def value = 'bar'
        assertTrue header.keySet().isEmpty()
        header.put(key, value)
        assertFalse header.keySet().isEmpty()
        assertEquals 1, header.keySet().size()
        assertEquals key, header.keySet().iterator().next()

        def i = header.keySet().iterator()
        i.next()
        i.remove() // assert keyset modification modifies state:
        assertTrue header.keySet().isEmpty()
    }

    @Test
    void testValues() {
        def key = 'foo'
        def value = 'bar'
        assertTrue header.values().isEmpty()
        header.put(key, value)
        assertFalse header.values().isEmpty()
        assertEquals 1, header.values().size()
        assertEquals value, header.values().iterator().next()

        def i = header.values().iterator()
        i.next()
        i.remove() // assert values modification modifies state:
        assertTrue header.values().isEmpty()
    }

    @Test
    void testEntrySet() {
        def key = 'foo'
        def value = 'bar'
        assertTrue header.entrySet().isEmpty()
        header.put(key, value)
        assertFalse header.entrySet().isEmpty()
        assertEquals 1, header.entrySet().size()
        def entry = header.entrySet().iterator().next()
        assertEquals key, entry.getKey()
        assertEquals value, entry.getValue()

        def i = header.entrySet().iterator()
        i.next()
        i.remove() // assert values modification modifies state:
        assertTrue header.entrySet().isEmpty()
    }

    @Test
    void testPut() {
        header.put('foo', 'bar')
        assertEquals 'bar', header.get('foo')
    }

    @Test
    void testPutAll() {
        def m = ['foo': 'bar', 'baz': 'bat']
        header.putAll(m)
        assertEquals m, header
    }

    @Test
    void testRemove() {
        header.put('foo', 'bar')
        assertFalse header.isEmpty()
        header.remove('foo')
        assertTrue header.isEmpty()
    }

    @Test
    void testClear() {
        def m = ['foo': 'bar', 'baz': 'bat']
        header.putAll(m)
        assertEquals m, header
        header.clear()
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

    @Test
    void testAlg() {
        assertSymmetry('algorithm', 'none')
        assertSymmetry('algorithm', 'HS256')
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
        assertSymmetry('jwkSetUrl', uri)
    }

    /**
     * Asserts that if the protected-header-only 'jwk' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testJwk() {
        def jwk = Jwks.builder().key(TestKeys.RS256.pair.public as RSAPublicKey).build()
        assertSymmetry('jwk', jwk)
    }

    /**
     * Asserts that if the protected-header-only 'kid' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testKeyId() {
        assertSymmetry('keyId', 'hello')
    }

    /**
     * Asserts that if the protected-header-only 'crit' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testCritical() {
        def crit = ['exp', 'sub'] as Set<String>
        assertSymmetry('critical', crit)
    }

    // ====================== X.509 Methods =======================

    /**
     * Asserts that if the protected-header-only 'x5u' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testX09Url() {
        def uri = URI.create('https://github.com/jwtk/jjwt')
        assertSymmetry('x509Url', uri)
    }

    /**
     * Asserts that if the protected-header-only 'x5c' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testX509CertificateChain() {
        def chain = TestKeys.RS256.chain
        assertSymmetry('x509CertificateChain', chain)
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

        header.x509CertificateSha1Thumbprint(x5t)
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
        def x5tS256 = Jwks.HASH.@SHA256.digest(request)
        String encoded = Encoders.BASE64URL.encode(x5tS256)

        header.x509CertificateSha256Thumbprint(x5tS256)
        assertArrayEquals x5tS256, header.getX509CertificateSha256Thumbprint()
        assertEquals encoded, header.get('x5t#S256')
    }

    // ====================== JWE Header Methods =======================

    @Test
    void testEncryptionAlgorithm() {
        def enc = Jwts.ENC.A256GCM.getId()
        header.put('enc', enc)
        assertEquals enc, header.getEncryptionAlgorithm()
    }

    @Test
    void testEphemeralPublicKey() {
        def key = TestKeys.ES256.pair.public
        def jwk = Jwks.builder().key(key).build()
        header.put('epk', jwk)
        assertEquals jwk, header.getEphemeralPublicKey()
    }

    @Test
    void testAgreementPartyUInfo() {
        def info = Strings.utf8("UInfo")
        assertSymmetry('agreementPartyUInfo', info)
    }

    @Test
    void testAgreementPartyUInfoString() {
        def s = "UInfo"
        def info = Strings.utf8(s)
        header.agreementPartyVInfo(s)
        assertArrayEquals info, header.getAgreementPartyVInfo()
    }

    @Test
    void testAgreementPartyVInfo() {
        def info = Strings.utf8("VInfo")
        assertSymmetry('agreementPartyVInfo', info)
    }

    @Test
    void testAgreementPartyVInfoString() {
        def s = "VInfo"
        def info = Strings.utf8(s)
        header.agreementPartyVInfo(s)
        assertArrayEquals info, header.getAgreementPartyVInfo()
    }

    @Test
    void testPbes2Salt() {
        byte[] salt = Bytes.randomBits(256)
        header.put('p2s', salt)
        assertArrayEquals salt, header.getPbes2Salt()
    }

    @Test
    void testPbes2Count() {
        int count = 4096
        assertSymmetry('pbes2Count', count)
    }

    @Test
    void testInitializationVector() {
        byte[] val = Bytes.randomBits(96)
        header.put('iv', val)
        assertArrayEquals val, header.getInitializationVector()
    }

    @Test
    void testAuthenticationTag() {
        byte[] val = Bytes.randomBits(128)
        header.put('tag', val)
        assertArrayEquals val, header.getAuthenticationTag()
    }
}
