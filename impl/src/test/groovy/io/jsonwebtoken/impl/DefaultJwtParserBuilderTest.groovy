/*
 * Copyright (C) 2019 jsonwebtoken.io
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

import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.*
import io.jsonwebtoken.impl.security.*
import io.jsonwebtoken.io.*
import io.jsonwebtoken.security.InvalidKeyException
import org.junit.Before
import org.junit.Test

import java.security.Provider

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

// NOTE to the casual reader: even though this test class appears mostly empty, the DefaultJwtParserBuilder
// implementation is tested to 100% coverage.  The vast majority of its tests are in the JwtsTest class.  This class
// just fills in any remaining test gaps.
class DefaultJwtParserBuilderTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()

    private DefaultJwtParserBuilder builder

    @Before
    void setUp() {
        builder = new DefaultJwtParserBuilder()
    }

    @Test
    void testCriticalEmtpy() {
        builder.critical().add(' ').and() // shouldn't modify the set
        assertTrue builder.@critical.isEmpty()
    }

    /**
     * Asserts that if a .critical() builder is used, and its .and() method is not called, the change to the
     * crit collection is still applied when building the parser.
     * @see <a href="https://github.com/jwtk/jjwt/issues/916">JJWT Issue 916</a>
     * @since 0.12.5
     */
    @Test
    void testCriticalWithoutConjunction() {
        builder.critical().add('foo') // no .and() call
        assertFalse builder.@critical.isEmpty()
        assertTrue builder.@critical.contains('foo')
        def parser = builder.build()
        assertFalse parser.@critical.isEmpty()
        assertTrue parser.@critical.contains('foo')
    }

    @Test
    void testSetProvider() {
        Provider provider = createMock(Provider)
        replay provider

        def parser = builder.provider(provider).build()

        assertSame provider, parser.provider
        verify provider
    }

    @Test
    void testKeyLocatorAndVerificationKeyConfigured() {
        try {
            builder
                    .keyLocator(new ConstantKeyLocator(null, null))
                    .verifyWith(TestKeys.HS256)
                    .build()
            fail()
        } catch (IllegalStateException e) {
            String msg = "Both 'keyLocator' and a 'verifyWith' key cannot be configured. Prefer 'keyLocator' if possible."
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testKeyLocatorAndDecryptionKeyConfigured() {
        try {
            builder
                    .keyLocator(new ConstantKeyLocator(null, null))
                    .decryptWith(TestKeys.A128GCM)
                    .build()
            fail()
        } catch (IllegalStateException e) {
            String msg = "Both 'keyLocator' and a 'decryptWith' key cannot be configured. Prefer 'keyLocator' if possible."
            assertEquals msg, e.getMessage()
        }
    }

    @Test(expected = IllegalArgumentException)
    void testBase64UrlDecodeWithNullArgument() {
        builder.base64UrlDecodeWith(null)
    }

    @Test
    void testBase64UrlEncodeWithCustomDecoder() {

        String jwt = Jwts.builder().claim('foo', 'bar').compact()

        boolean invoked = false
        Decoder<String, byte[]> decoder = new Decoder<String, byte[]>() {
            @Override
            byte[] decode(String s) throws DecodingException {
                invoked = true
                return Decoders.BASE64URL.decode(s)
            }
        }
        def parser = builder.base64UrlDecodeWith(decoder).unsecured().build()
        assertFalse invoked

        assertEquals 'bar', parser.parseUnsecuredClaims(jwt).getPayload().get('foo')
        assertTrue invoked
    }

    @Test(expected = IllegalArgumentException)
    void testDeserializeJsonWithNullArgument() {
        builder.deserializeJsonWith(null)
    }

    @Test
    void testDeserializeJsonWithCustomSerializer() {
        def deserializer = new AbstractDeserializer() {
            @Override
            protected Object doDeserialize(Reader reader) throws Exception {
                return OBJECT_MAPPER.readValue(reader, Map.class)
            }
        }
        def p = builder.deserializeJsonWith(deserializer)
        assertSame deserializer, p.@deserializer

        def alg = Jwts.SIG.HS256
        def key = alg.key().build()

        String jws = Jwts.builder().claim('foo', 'bar').signWith(key, alg).compact()

        assertEquals 'bar', p.verifyWith(key).build().parseSignedClaims(jws).getPayload().get('foo')
    }

    @Test
    void testMaxAllowedClockSkewSeconds() {
        long max = Long.MAX_VALUE / 1000 as long
        builder.setAllowedClockSkewSeconds(max) // no exception should be thrown
    }

    @Test
    void testExceededAllowedClockSkewSeconds() {
        long value = Long.MAX_VALUE / 1000 as long
        value = value + 1L
        try {
            builder.setAllowedClockSkewSeconds(value)
        } catch (IllegalArgumentException expected) {
            assertEquals DefaultJwtParserBuilder.MAX_CLOCK_SKEW_ILLEGAL_MSG, expected.message
        }
    }

    @Test
    void testCompressionCodecResolver() {
        def resolver = new CompressionCodecResolver() {
            @Override
            CompressionCodec resolveCompressionCodec(Header header) throws CompressionException {
                return null
            }
        }
        def parser = builder.setCompressionCodecResolver(resolver).build()
        assertSame resolver, parser.zipAlgs.resolver
    }

    @Test
    void testAddCompressionAlgorithms() {
        def codec = new TestCompressionCodec(id: 'test')
        def parser = builder.zip().add(codec).and().build()
        def header = Jwts.header().add('zip', codec.getId()).build()
        assertSame codec, parser.zipAlgs.locate(header)
    }

    /**
     * Asserts that if a .zip() builder is used, and its .and() method is not called, the change to the
     * compression algorithm collection is still applied when building the parser.
     * @see <a href="https://github.com/jwtk/jjwt/issues/916">JJWT Issue 916</a>
     * @since 0.12.5
     */
    @Test
    void testAddCompressionAlgorithmWithoutConjunction() {
        def codec = new TestCompressionCodec(id: 'test')
        builder.zip().add(codec) // no .and() call
        def parser = builder.build()
        def header = Jwts.header().add('zip', codec.getId()).build()
        assertSame codec, parser.zipAlgs.locate(header)
    }

    @Test
    void testAddCompressionAlgorithmsOverrideDefaults() {
        def header = Jwts.header().add('zip', 'DEF').build()
        def parser = builder.build()
        assertSame Jwts.ZIP.DEF, parser.zipAlgs.apply(header) // standard implementation default

        def alg = new TestCompressionCodec(id: 'DEF') // custom impl with standard identifier
        parser = builder.zip().add(alg).and().build()
        assertSame alg, parser.zipAlgs.apply(header) // custom one, not standard impl
    }

    @Test
    void testCaseSensitiveCompressionAlgorithm() {
        def standard = Jwts.header().add('zip', 'DEF').build()
        def nonStandard = Jwts.header().add('zip', 'def').build()
        def parser = builder.build()
        assertSame Jwts.ZIP.DEF, parser.zipAlgs.apply(standard) // standard implementation default
        try {
            parser.zipAlgs.apply(nonStandard)
            fail()
        } catch (UnsupportedJwtException e) {
            String msg = "Unrecognized JWT ${DefaultHeader.COMPRESSION_ALGORITHM} header value: def"
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testAddEncryptionAlgorithmsOverrideDefaults() {
        final String standardId = Jwts.ENC.A256GCM.getId()
        def header = Jwts.header().add('enc', standardId).build()
        def parser = builder.build()
        assertSame Jwts.ENC.A256GCM, parser.encAlgs.apply(header) // standard implementation default

        def custom = new TestAeadAlgorithm(id: standardId) // custom impl with standard identifier
        parser = builder.enc().add(custom).and().build()
        assertSame custom, parser.encAlgs.apply(header) // custom one, not standard impl
    }

    /**
     * Asserts that if an .enc() builder is used, and its .and() method is not called, the change to the
     * encryption algorithm collection is still applied when building the parser.
     * @see <a href="https://github.com/jwtk/jjwt/issues/916">JJWT Issue 916</a>
     * @since 0.12.5
     */
    @Test
    void testAddEncryptionAlgorithmWithoutConjunction() {
        def alg = new TestAeadAlgorithm(id: 'test')
        builder.enc().add(alg) // no .and() call
        def parser = builder.build() as DefaultJwtParser
        def header = Jwts.header().add('alg', 'foo').add('enc', alg.getId()).build() as JweHeader
        assertSame alg, parser.encAlgs.apply(header)
    }

    @Test
    void testCaseSensitiveEncryptionAlgorithm() {
        def alg = Jwts.ENC.A256GCM
        def standard = Jwts.header().add('alg', 'foo').add('enc', alg.id).build()
        def nonStandard = Jwts.header().add('alg', 'foo').add('enc', alg.id.toLowerCase()).build()
        def parser = builder.build()
        assertSame alg, parser.encAlgs.apply(standard) // standard id
        try {
            parser.encAlgs.apply(nonStandard) // non-standard id
            fail()
        } catch (UnsupportedJwtException e) {
            String msg = "Unrecognized JWE ${DefaultJweHeader.ENCRYPTION_ALGORITHM} header value: ${alg.id.toLowerCase()}"
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testAddKeyAlgorithmsOverrideDefaults() {
        final String standardId = Jwts.KEY.A256GCMKW.id
        def header = Jwts.header().add('enc', Jwts.ENC.A256GCM.id).add('alg', standardId).build()
        def parser = builder.build()
        assertSame Jwts.KEY.A256GCMKW, parser.keyAlgs.apply(header) // standard implementation default

        def custom = new TestKeyAlgorithm(id: standardId) // custom impl with standard identifier
        parser = builder.key().add(custom).and().build()
        assertSame custom, parser.keyAlgs.apply(header) // custom one, not standard impl
    }

    /**
     * Asserts that if an .key() builder is used, and its .and() method is not called, the change to the
     * key algorithm collection is still applied when building the parser.
     * @see <a href="https://github.com/jwtk/jjwt/issues/916">JJWT Issue 916</a>
     * @since 0.12.5
     */
    @Test
    void testAddKeyAlgorithmWithoutConjunction() {
        def alg = new TestKeyAlgorithm(id: 'test')
        builder.key().add(alg) // no .and() call
        def parser = builder.build() as DefaultJwtParser
        def header = Jwts.header()
                .add('enc', 'foo')
                .add('alg', alg.getId()).build() as JweHeader
        assertSame alg, parser.keyAlgs.apply(header)
    }

    @Test
    void testCaseSensitiveKeyAlgorithm() {
        def alg = Jwts.KEY.A256GCMKW
        def hb = Jwts.header().add('enc', Jwts.ENC.A256GCM.id)
        def standard = hb.add('alg', alg.id).build()
        def nonStandard = hb.add('alg', alg.id.toLowerCase()).build()
        def parser = builder.build()
        assertSame alg, parser.keyAlgs.apply(standard) // standard id
        try {
            parser.keyAlgs.apply(nonStandard) // non-standard id
            fail()
        } catch (UnsupportedJwtException e) {
            String msg = "Unrecognized JWE ${DefaultJweHeader.ALGORITHM} header value: ${alg.id.toLowerCase()}"
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testAddSignatureAlgorithmsOverrideDefaults() {
        final String standardId = Jwts.SIG.HS256.id
        def header = Jwts.header().add('alg', standardId).build()
        def parser = builder.build()
        assertSame Jwts.SIG.HS256, parser.sigAlgs.apply(header) // standard implementation default

        def custom = new TestMacAlgorithm(id: standardId) // custom impl with standard identifier
        parser = builder.sig().add(custom).and().build()
        assertSame custom, parser.sigAlgs.apply(header) // custom one, not standard impl
    }

    /**
     * Asserts that if an .sig() builder is used, and its .and() method is not called, the change to the
     * signature algorithm collection is still applied when building the parser.
     * @see <a href="https://github.com/jwtk/jjwt/issues/916">JJWT Issue 916</a>
     * @since 0.12.5
     */
    @Test
    void testAddSignatureAlgorithmWithoutConjunction() {
        def alg = new TestMacAlgorithm(id: 'test')
        builder.sig().add(alg) // no .and() call
        def parser = builder.build() as DefaultJwtParser
        def header = Jwts.header().add('alg', alg.getId()).build() as JwsHeader
        assertSame alg, parser.sigAlgs.apply(header)
    }

    @Test
    void testCaseSensitiveSignatureAlgorithm() {
        def alg = Jwts.SIG.HS256
        def hb = Jwts.header().add('alg', alg.id)
        def standard = hb.build()
        def nonStandard = hb.add('alg', alg.id.toLowerCase()).build()
        def parser = builder.build()
        assertSame alg, parser.sigAlgs.apply(standard) // standard id
        try {
            parser.sigAlgs.apply(nonStandard) // non-standard id
            fail()
        } catch (UnsupportedJwtException e) {
            String msg = "Unrecognized JWS ${DefaultJwsHeader.ALGORITHM} header value: ${alg.id.toLowerCase()}"
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testCompressionCodecResolverAndExtraCompressionCodecs() {
        def codec = new TestCompressionCodec(id: 'test')
        def resolver = new CompressionCodecResolver() {
            @Override
            CompressionCodec resolveCompressionCodec(Header header) throws CompressionException {
                return null
            }
        }
        try {
            builder.setCompressionCodecResolver(resolver).zip().add(codec).and().build()
            fail()
        } catch (IllegalStateException expected) {
            String msg = "Both 'zip()' and 'compressionCodecResolver' cannot be configured. Choose either."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testEnableUnsecuredDecompressionWithoutEnablingUnsecuredJws() {
        try {
            builder.unsecuredDecompression().build()
            fail()
        } catch (IllegalStateException ise) {
            String expected = "'unsecuredDecompression' is only relevant if 'unsecured' " + "is also configured. Please read the JavaDoc of both features before enabling either " + "due to their security implications."
            assertEquals expected, ise.getMessage()
        }
    }

    @Test
    void testDecompressUnprotectedJwtDefault() {
        def codec = Jwts.ZIP.GZIP
        String jwt = Jwts.builder().compressWith(codec).setSubject('joe').compact()
        try {
            builder.unsecured().build().parse(jwt)
            fail()
        } catch (UnsupportedJwtException e) {
            String expected = String.format(DefaultJwtParser.UNPROTECTED_DECOMPRESSION_MSG, codec.getId())
            assertEquals(expected, e.getMessage())
        }
    }

    @Test
    void testDecompressUnprotectedJwtEnabled() {
        def codec = Jwts.ZIP.GZIP
        String jws = Jwts.builder().compressWith(codec).setSubject('joe').compact()
        def jwt = builder.unsecured().unsecuredDecompression().build().parse(jws)
        assertEquals 'joe', ((Claims) jwt.getPayload()).getSubject()
    }

    @Test
    void testDefaultDeserializer() {
        JwtParser parser = builder.build() // perform ServiceLoader lookup
        assertTrue parser.@deserializer instanceof Deserializer
    }

    @Test
    void testUserSetDeserializerWrapped() {
        Deserializer deserializer = niceMock(Deserializer)
        JwtParser parser = builder.deserializeJsonWith(deserializer).build()
        assertSame deserializer, parser.@deserializer
    }

    @Test
    void testVerificationKeyAndSigningKeyResolverBothConfigured() {
        def key = TestKeys.HS256
        builder.verifyWith(key).setSigningKeyResolver(new LocatingKeyResolver(new ConstantKeyLocator(key, null)))
        try {
            builder.build()
            fail()
        } catch (IllegalStateException expected) {
            String msg = "Both a 'signingKeyResolver and a 'verifyWith' key cannot be configured. " + "Choose either, or prefer `keyLocator` when possible."
            assertEquals(msg, expected.getMessage())
        }
    }

    @Test
    void testSetSigningKeyWithPrivateKey() {
        try {
            builder.setSigningKey(TestKeys.RS256.pair.private)
            fail()
        } catch (InvalidKeyException e) {
            String msg = 'JWS verification key must be either a SecretKey (for MAC algorithms) or a PublicKey (for Signature algorithms).'
            assertEquals msg, e.getMessage()
        }
    }

    static class TestCompressionCodec implements CompressionCodec {

        String id

        @Override
        String getAlgorithmName() {
            return this.id
        }

        @Override
        String getId() {
            return this.id
        }

        @Override
        byte[] compress(byte[] content) throws CompressionException {
            return new byte[0]
        }

        @Override
        byte[] decompress(byte[] compressed) throws CompressionException {
            return new byte[0]
        }

        @Override
        OutputStream compress(OutputStream out) throws CompressionException {
            return out
        }

        @Override
        InputStream decompress(InputStream inputStream) throws CompressionException {
            return inputStream
        }
    }

}
