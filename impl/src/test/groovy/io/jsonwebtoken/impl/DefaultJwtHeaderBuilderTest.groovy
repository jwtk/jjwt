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
import io.jsonwebtoken.ProtectedHeader
import io.jsonwebtoken.impl.io.Streams
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.security.DefaultHashAlgorithm
import io.jsonwebtoken.impl.security.DefaultRequest
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Collections
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.Jwks
import org.junit.Before
import org.junit.Test

import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.*

class DefaultJwtHeaderBuilderTest {

    static DefaultJwtHeaderBuilder builder
    static def header

    static DefaultJwtHeaderBuilder jws() {
        // assignment and return must be on different lines when testing on JDK 7:
        builder = new DefaultJwtHeaderBuilder().add('alg', 'foo') as DefaultJwtHeaderBuilder
        return builder
    }

    static DefaultJwtHeaderBuilder jwe() {
        // assignment and return must be on different lines when testing on JDK 7 otherwise we get
        // (class: io/jsonwebtoken/impl/DefaultJwtHeaderBuilderTest, method: jwe signature: ()Lio/jsonwebtoken/impl/DefaultJwtHeaderBuilder;) Illegal target of jump or branch
        builder = jws().add('enc', 'bar') as DefaultJwtHeaderBuilder
        return builder
    }

    @Before
    void setUp() {
        header = null
        builder = new DefaultJwtHeaderBuilder()
    }

    @SuppressWarnings('GroovyAssignabilityCheck')
    private static void assertSymmetry(String propName, def val) {
        def name = Strings.capitalize(propName)
        switch (propName) {
            case 'algorithm': builder.add('alg', val); break // no setter
            case 'compressionAlgorithm': builder.add('zip', val); break // no setter
            default: builder."$propName"(val)
        }
        header = builder.build()
        if (val instanceof byte[]) {
            assertArrayEquals val, header."get$name"()
        } else {
            assertEquals val, header."get$name"()
        }
    }

    @Test
    void testStaticFactoryMethod() {
        assertTrue Jwts.header() instanceof DefaultJwtHeaderBuilder
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
        builder.put('foo', 'bar')
        assertEquals 1, builder.build().size()
    }

    @Test
    void testIsEmpty() {
        assertTrue builder.build().isEmpty()
        builder.put('foo', 'bar')
        assertFalse builder.build().isEmpty()
    }

    @Test
    void testContainsKey() {
        def key = 'foo'
        assertFalse builder.build().containsKey(key)
        builder.put(key, 'bar')
        assertTrue builder.build().containsKey(key)
    }

    @Test
    void testContainsValue() {
        def value = 'bar'
        assertFalse builder.build().containsValue(value)
        builder.put('foo', value)
        assertTrue builder.build().containsValue(value)
    }

    @Test
    void testGet() {
        def key = 'foo'
        def value = 'bar'
        assertNull builder.build().get(key)
        builder.put(key, value)
        assertEquals value, builder.build().get(key)
    }

    @Test
    void testKeySet() {
        def key = 'foo'
        def value = 'bar'
        assertTrue builder.build().keySet().isEmpty()

        builder.put(key, value)
        def built = builder.build()
        assertFalse built.keySet().isEmpty()
        assertEquals 1, built.keySet().size()
        assertEquals key, built.keySet().iterator().next()

        def i = builder.build().keySet().iterator()
        i.next()
        //built headers are immutable:
        try {
            i.remove() // assert keyset modification modifies builder state:
            fail()
        } catch (UnsupportedOperationException expected) {
        }
    }

    @Test
    void testValues() {
        def key = 'foo'
        def value = 'bar'
        assertTrue builder.build().values().isEmpty()

        builder.put(key, value)
        assertFalse builder.build().values().isEmpty()
        assertEquals 1, builder.build().values().size()
        assertEquals value, builder.build().values().iterator().next()

        def i = builder.build().values().iterator()
        i.next()
        //built headers are immutable:
        try {
            i.remove()
            fail()
        } catch (UnsupportedOperationException expected) {
        }
    }

    @Test
    void testEntrySet() {
        def key = 'foo'
        def value = 'bar'
        assertTrue builder.build().entrySet().isEmpty()

        builder.put(key, value)
        assertFalse builder.build().entrySet().isEmpty()
        assertEquals 1, builder.build().entrySet().size()
        def entry = builder.build().entrySet().iterator().next()
        assertEquals key, entry.getKey()
        assertEquals value, entry.getValue()

        def i = builder.build().entrySet().iterator()
        i.next()
        //built headers are immutable:
        try {
            i.remove()
            fail()
        } catch (UnsupportedOperationException expected) {
        }
    }

    @Test
    void testPut() {
        builder.put('foo', 'bar')
        assertEquals 'bar', builder.build().get('foo')
    }

    @Test
    void testPutAll() {
        def m = ['foo': 'bar', 'baz': 'bat']
        def header = builder.add(m).build()
        assertEquals m, header
    }

    @Test
    void testRemove() {
        builder.put('foo', 'bar')
        assertEquals 'bar', builder.build().foo

        builder.remove('foo')
        assertTrue builder.build().isEmpty()
    }

    @Test
    void testClear() {
        def m = ['foo': 'bar', 'baz': 'bat']
        builder.add(m)
        builder.clear()
        def header = builder.build()
        assertTrue header.isEmpty()
    }

    @Test
    void testEmpty() {
        def m = ['foo': 'bar', 'baz': 'bat']
        def header = builder.add(m).empty().build()
        assertTrue header.isEmpty()
    }

    @Test
    void testToMap() {
        def m = ['foo': 'bar', 'baz': 'bat']
        builder.putAll(m)
        assertEquals m, builder
        assertEquals m, builder.build()
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

    @Test
    void testDeprecatedSetters() { // TODO: remove before 1.0
        assertEquals 'foo', builder.setType('foo').build().getType()

        assertEquals 'foo', builder.setContentType('foo').build().get('cty') // compact form
        assertEquals 'application/foo', builder.build().getContentType()     // normalized form

        assertEquals 'foo', builder.setCompressionAlgorithm('foo').build().getCompressionAlgorithm()
        assertEquals 'foo', jws().setKeyId('foo').build().getKeyId()
        assertEquals 'foo', jws().setAlgorithm('foo').build().getAlgorithm()
    }

    // ====================== Protected Header Methods =======================

    /**
     * Asserts that if the protected-header-only 'jku' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testJwkSetUrl() {
        URI uri = URI.create('https://github.com/jwtk/jjwt')
        header = jws().jwkSetUrl(uri).build() as JwsHeader
        assertEquals uri, header.getJwkSetUrl()
    }

    /**
     * Asserts that if the protected-header-only 'jwk' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testJwk() {
        def jwk = Jwks.builder().key(TestKeys.RS256.pair.public as RSAPublicKey).build()
        header = jws().jwk(jwk).build() as JwsHeader
        assertEquals jwk, header.getJwk()
    }

    /**
     * Asserts that if the protected-header-only 'kid' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testKeyId() {
        def kid = 'whatever'
        header = jws().keyId(kid).build() as JwsHeader
        assertEquals kid, header.getKeyId()
    }

    /**
     * Asserts that if the protected-header-only 'crit' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testCritical() {
        def crit = ['foo'] as Set<String>
        header = jws().add('foo', 'bar').critical().add(crit).and().build() as JwsHeader
        assertTrue header instanceof JwsHeader
        assertFalse header instanceof JweHeader
        assertEquals crit, header.getCritical()
    }

    // ====================== X.509 Methods =======================

    /**
     * Asserts that if the protected-header-only 'x5u' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testX09Url() {
        def uri = URI.create('https://github.com/jwtk/jjwt')
        header = jws().x509Url(uri).build() as JwsHeader
        assertEquals uri, header.getX509Url()
    }

    /**
     * Asserts that if the protected-header-only 'x5c' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testX509CertificateChain() {
        def chain = TestKeys.RS256.chain
        header = jws().x509Chain(chain).build() as JwsHeader
        assertEquals chain, header.getX509Chain()
    }

    /**
     * Asserts that if the protected-header-only 'x5t' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testX509CertificateSha1Thumbprint() {
        def payload = Streams.of(TestKeys.RS256.cert.getEncoded())
        def request = new DefaultRequest(payload, null, null)
        def x5t = DefaultHashAlgorithm.SHA1.digest(request)
        String encoded = Encoders.BASE64URL.encode(x5t)

        header = jws().x509Sha1Thumbprint(x5t).build() as JwsHeader
        assertArrayEquals x5t, header.getX509Sha1Thumbprint()
        assertEquals encoded, header.get('x5t')
    }

    @Test
    void testX509CertificateSha1ThumbprintEnabled() {
        def chain = TestKeys.RS256.chain
        def payload = Streams.of(chain[0].getEncoded())
        def request = new DefaultRequest(payload, null, null)
        def x5t = DefaultHashAlgorithm.SHA1.digest(request)
        String encoded = Encoders.BASE64URL.encode(x5t)
        header = jws().x509Chain(chain).x509Sha1Thumbprint(true).build() as JwsHeader
        assertArrayEquals x5t, header.getX509Sha1Thumbprint()
        assertEquals encoded, header.get('x5t')
    }

    /**
     * Asserts that if the protected-header-only 'x5t#S256' member is set, but no JWE-only members are set, a
     * JwsHeader is created.
     */
    @Test
    void testX509CertificateSha256Thumbprint() {
        def payload = Streams.of(TestKeys.RS256.cert.getEncoded())
        def request = new DefaultRequest(payload, null, null)
        def x5tS256 = Jwks.HASH.@SHA256.digest(request)
        String encoded = Encoders.BASE64URL.encode(x5tS256)
        header = jws().x509Sha256Thumbprint(x5tS256).build() as JwsHeader
        assertArrayEquals x5tS256, header.getX509Sha256Thumbprint()
        assertEquals encoded, header.get('x5t#S256')
    }

    @Test
    void testX509CertificateSha256ThumbprintEnabled() {
        def chain = TestKeys.RS256.chain
        def payload = Streams.of(chain[0].getEncoded())
        def request = new DefaultRequest(payload, null, null)
        def x5tS256 = Jwks.HASH.SHA256.digest(request)
        String encoded = Encoders.BASE64URL.encode(x5tS256)
        header = jws().x509Chain(chain).x509Sha256Thumbprint(true).build() as JwsHeader
        assertArrayEquals x5tS256, header.getX509Sha256Thumbprint()
        assertEquals encoded, header.get('x5t#S256')
    }

    // ====================== JWE Header Methods =======================

    @Test
    void testEncryptionAlgorithm() {
        def enc = Jwts.ENC.A256GCM.getId()
        header = builder.add('alg', Jwts.KEY.A192KW.getId()).add('enc', enc).build() as JweHeader
        assertEquals enc, header.getEncryptionAlgorithm()
    }

    @Test
    void testEphemeralPublicKey() {
        def key = TestKeys.ES256.pair.public
        def jwk = Jwks.builder().key(key).build()
        header = jwe().add('epk', jwk).build() as JweHeader
        assertEquals jwk, header.getEphemeralPublicKey()
    }

    @Test
    void testAgreementPartyUInfo() {
        def info = Strings.utf8("UInfo")
        def header = jwe().agreementPartyUInfo(info).build() as JweHeader
        assertArrayEquals info, header.getAgreementPartyUInfo()
    }

    @Test
    void testAgreementPartyUInfoString() {
        def s = "UInfo"
        def info = Strings.utf8(s)
        def header = jwe().agreementPartyUInfo(s).build() as JweHeader
        assertArrayEquals info, header.getAgreementPartyUInfo()
    }

    @Test
    void testAgreementPartyVInfo() {
        def info = Strings.utf8("VInfo")
        def header = jwe().agreementPartyVInfo(info).build() as JweHeader
        assertArrayEquals info, header.getAgreementPartyVInfo()
    }

    @Test
    void testAgreementPartyVInfoString() {
        def s = "VInfo"
        def info = Strings.utf8(s)
        def header = jwe().agreementPartyVInfo(s).build() as JweHeader
        assertArrayEquals info, header.getAgreementPartyVInfo()
    }

    @Test
    void testPbes2Salt() {
        byte[] salt = Bytes.randomBits(256)
        def header = jwe().add('p2s', salt).build() as JweHeader
        assertArrayEquals salt, header.getPbes2Salt()
    }

    @Test
    void testPbes2Count() {
        int count = 4096
        def header = jwe().pbes2Count(count).build() as JweHeader
        assertEquals count, header.getPbes2Count()
    }

    @Test
    void testInitializationVector() {
        byte[] iv = Bytes.randomBits(96)
        def header = jwe().add('iv', iv).build() as JweHeader
        assertArrayEquals iv, header.getInitializationVector()
    }

    @Test
    void testAuthenticationTag() {
        byte[] val = Bytes.randomBits(128)
        def header = jwe().add('tag', val).build() as JweHeader
        assertArrayEquals val, header.getAuthenticationTag()
    }

    @Test
    void testUnprotectedHeaderChangedToProtectedHeaderChangedToJweHeader() {
        builder.put('foo', 'bar')
        assertEquals new DefaultHeader([foo: 'bar']), builder.build()

        // add JWS-required property:
        builder.put(DefaultHeader.ALGORITHM.getId(), 'HS256')
        assertEquals new DefaultJwsHeader([foo: 'bar', alg: 'HS256']), builder.build()

        // add JWE required property:
        builder.put(DefaultJweHeader.ENCRYPTION_ALGORITHM.getId(), Jwts.ENC.A256GCM.getId())
        assertEquals new DefaultJweHeader([foo: 'bar', alg: 'HS256', enc: 'A256GCM']), builder.build()
    }

    @Test
    void testCritSingle() {
        def crit = 'test'
        def header = jws().add(crit, 'foo').critical().add(crit).and().build() as ProtectedHeader
        def expected = [crit] as Set<String>
        assertEquals expected, header.getCritical()
    }

    /**
     * Asserts that if a .critical() builder is used, and its .and() method is not called, the change to the
     * crit collection is still applied when building the header.
     * @see <a href="https://github.com/jwtk/jjwt/issues/916">JJWT Issue 916</a>
     * @since 0.12.5
     */
    @Test
    void testCritWithoutConjunction() {
        def crit = 'test'
        def builder = jws()
        builder.add(crit, 'foo').critical().add(crit) // no .and() method
        def header = builder.build() as ProtectedHeader
        def expected = [crit] as Set<String>
        assertEquals expected, header.getCritical()
    }

    @Test
    void testCritSingleNullIgnored() {
        def crit = 'test'
        def expected = [crit] as Set<String>
        def header = jws().add(crit, 'foo').critical().add(crit).and().build() as ProtectedHeader
        assertEquals expected, header.getCritical()
        header = builder.critical().add((String) null).and().build() as ProtectedHeader // ignored
        assertEquals expected, header.getCritical() // nothing changed
    }

    @Test
    void testCritNullCollectionIgnored() {
        def crit = ['test'] as Set<String>
        def header = jws().add('test', 'foo').critical().add(crit).and().build() as ProtectedHeader
        assertEquals crit, header.getCritical()
        header = builder.critical().add((Collection) null).and().build() as ProtectedHeader
        assertEquals crit, header.getCritical() // nothing changed
    }

    @Test
    void testCritCollectionWithNullElement() {
        def crit = [null] as Set<String>
        def header = jws().add('test', 'foo').critical().add(crit).and().build() as ProtectedHeader
        assertNull header.getCritical()
    }

    @Test
    void testCritEmptyIgnored() {
        def crit = ['test'] as Set<String>
        ProtectedHeader header = jws().add('test', 'foo').critical().add(crit).and().build() as ProtectedHeader
        assertEquals crit, header.getCritical()
        header = builder.critical().add([] as Set<String>).and().build() as ProtectedHeader
        assertEquals crit, header.getCritical() // ignored
    }

    /**
     * Asserts that per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11, a {@code crit} header is not
     * allowed in non-protected headers.
     */
    @Test
    void testCritRemovedForUnprotectedHeader() {
        def crit = Collections.setOf('foo', 'bar')
        // no JWS or JWE params specified:
        def header = builder.add('test', 'value').critical().add(crit).and().build()
        assertFalse header.containsKey(DefaultProtectedHeader.CRIT.getId())
    }

    /**
     * Asserts that per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11, a value in the {@code crit} set
     * is removed if the corresponding header parameter is missing.
     */
    @Test
    void testCritNamesSanitizedWhenHeaderMissingCorrespondingParameter() {
        def critGiven = ['foo', 'bar'] as Set<String>
        def critExpected = ['foo'] as Set<String>
        def header = jws().add('foo', 'fooVal').critical().add(critGiven).and().build() as ProtectedHeader
        // header didn't set the 'bar' parameter, so 'bar' should not be in the crit values:
        assertEquals critExpected, header.getCritical()
    }

    @Test
    void testCritNamesRemovedWhenHeaderMissingCorrespondingParameter() {
        def critGiven = ['foo'] as Set<String>
        ProtectedHeader header = jws().critical().add(critGiven).and().build() as ProtectedHeader
        // header didn't set the 'foo' parameter, so crit would have been empty, and then removed from the header:
        assertNull header.getCritical()
    }
}
