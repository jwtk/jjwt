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
import io.jsonwebtoken.impl.security.ConstantKeyLocator
import io.jsonwebtoken.impl.security.LocatingKeyResolver
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Decoder
import io.jsonwebtoken.io.DecodingException
import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.security.*
import org.hamcrest.CoreMatchers
import org.junit.Before
import org.junit.Test

import javax.crypto.SecretKey
import java.security.Provider

import static org.easymock.EasyMock.*
import static org.hamcrest.MatcherAssert.assertThat
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
        def decoder = new Decoder() {
            @Override
            Object decode(Object o) throws DecodingException {
                return null
            }
        }
        def b = builder.base64UrlDecodeWith(decoder).build()
        assertSame decoder, b.decoder
    }

    @Test(expected = IllegalArgumentException)
    void testDeserializeJsonWithNullArgument() {
        builder.deserializeJsonWith(null)
    }

    @Test
    void testDeserializeJsonWithCustomSerializer() {
        def deserializer = new Deserializer() {
            @Override
            Object deserialize(byte[] bytes) throws DeserializationException {
                return OBJECT_MAPPER.readValue(bytes, Map.class)
            }
        }
        def p = builder.deserializeJsonWith(deserializer)
        assertSame deserializer, p.deserializer

        def alg = Jwts.SIG.HS256
        def key = alg.key().build()

        String jws = Jwts.builder().claim('foo', 'bar').signWith(key, alg).compact()

        assertEquals 'bar', p.verifyWith(key).build().parseClaimsJws(jws).getPayload().get('foo')
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
        assertSame resolver, parser.zipAlgFn.resolver
    }

    @Test
    void testAddCompressionAlgorithms() {
        def codec = new TestCompressionCodec(id: 'test')
        def parser = builder.addCompressionAlgorithms([codec] as Set<CompressionCodec>).build()
        def header = Jwts.header().add('zip', codec.getId()).build()
        assertSame codec, parser.zipAlgFn.locate(header)
    }

    @Test
    void testAddCompressionAlgorithmsOverrideDefaults() {
        def header = Jwts.header().add('zip', 'DEF').build()
        def parser = builder.build()
        assertSame Jwts.ZIP.DEF, parser.zipAlgFn.apply(header) // standard implementation default

        def alg = new TestCompressionCodec(id: 'DEF') // custom impl with standard identifier
        parser = builder.addCompressionAlgorithms([alg]).build()
        assertSame alg, parser.zipAlgFn.apply(header) // custom one, not standard impl
    }

    @Test
    void testCaseSensitiveCompressionAlgorithm() {
        def standard = Jwts.header().add('zip', 'DEF').build()
        def nonStandard = Jwts.header().add('zip', 'def').build()
        def parser = builder.build()
        assertSame Jwts.ZIP.DEF, parser.zipAlgFn.apply(standard) // standard implementation default
        try {
            parser.zipAlgFn.apply(nonStandard)
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
        assertSame Jwts.ENC.A256GCM, parser.encAlgFn.apply(header) // standard implementation default

        def custom = new TestAeadAlgorithm(id: standardId) // custom impl with standard identifier
        parser = builder.addEncryptionAlgorithms([custom]).build()
        assertSame custom, parser.encAlgFn.apply(header) // custom one, not standard impl
    }

    @Test
    void testCaseSensitiveEncryptionAlgorithm() {
        def alg = Jwts.ENC.A256GCM
        def standard = Jwts.header().add('enc', alg.id).build()
        def nonStandard = Jwts.header().add('enc', alg.id.toLowerCase()).build()
        def parser = builder.build()
        assertSame alg, parser.encAlgFn.apply(standard) // standard id
        try {
            parser.encAlgFn.apply(nonStandard) // non-standard id
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
        assertSame Jwts.KEY.A256GCMKW, parser.keyAlgFn.apply(header) // standard implementation default

        def custom = new TestKeyAlgorithm(id: standardId) // custom impl with standard identifier
        parser = builder.addKeyAlgorithms([custom]).build()
        assertSame custom, parser.keyAlgFn.apply(header) // custom one, not standard impl
    }

    @Test
    void testCaseSensitiveKeyAlgorithm() {
        def alg = Jwts.KEY.A256GCMKW
        def hb = Jwts.header().add('enc', Jwts.ENC.A256GCM.id)
        def standard = hb.add('alg', alg.id).build()
        def nonStandard = hb.add('alg', alg.id.toLowerCase()).build()
        def parser = builder.build()
        assertSame alg, parser.keyAlgFn.apply(standard) // standard id
        try {
            parser.keyAlgFn.apply(nonStandard) // non-standard id
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
        assertSame Jwts.SIG.HS256, parser.sigAlgFn.apply(header) // standard implementation default

        def custom = new TestMacAlgorithm(id: standardId) // custom impl with standard identifier
        parser = builder.addSignatureAlgorithms([custom]).build()
        assertSame custom, parser.sigAlgFn.apply(header) // custom one, not standard impl
    }

    @Test
    void testCaseSensitiveSignatureAlgorithm() {
        def alg = Jwts.SIG.HS256
        def hb = Jwts.header().add('alg', alg.id)
        def standard = hb.build()
        def nonStandard = hb.add('alg', alg.id.toLowerCase()).build()
        def parser = builder.build()
        assertSame alg, parser.sigAlgFn.apply(standard) // standard id
        try {
            parser.sigAlgFn.apply(nonStandard) // non-standard id
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
            builder.setCompressionCodecResolver(resolver).addCompressionAlgorithms([codec] as Set<CompressionCodec>).build()
            fail()
        } catch (IllegalStateException expected) {
            String msg = "Both 'addCompressionAlgorithms' and 'compressionCodecResolver' cannot be specified. Choose either."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testEnableUnsecuredDecompressionWithoutEnablingUnsecuredJws() {
        try {
            builder.enableUnsecuredDecompression().build()
            fail()
        } catch (IllegalStateException ise) {
            String expected = "'enableUnsecuredDecompression' is only relevant if 'enableUnsecured' " + "is also configured. Please read the JavaDoc of both features before enabling either " + "due to their security implications."
            assertEquals expected, ise.getMessage()
        }
    }

    @Test
    void testDecompressUnprotectedJwtDefault() {
        def codec = Jwts.ZIP.GZIP
        String jwt = Jwts.builder().compressWith(codec).setSubject('joe').compact()
        try {
            builder.enableUnsecured().build().parse(jwt)
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
        def jwt = builder.enableUnsecured().enableUnsecuredDecompression().build().parse(jws)
        assertEquals 'joe', ((Claims) jwt.getPayload()).getSubject()
    }

    @Test
    void testDefaultDeserializer() {
        JwtParser parser = builder.build()
        assertThat parser.deserializer, CoreMatchers.instanceOf(JwtDeserializer)
    }

    @Test
    void testUserSetDeserializerWrapped() {
        Deserializer deserializer = niceMock(Deserializer)
        JwtParser parser = builder.deserializeJsonWith(deserializer).build()

        assertThat parser.deserializer, CoreMatchers.instanceOf(JwtDeserializer)
        assertSame deserializer, parser.deserializer.deserializer
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
    }

    static class TestAeadAlgorithm implements AeadAlgorithm {

        String id
        int keyBitLength = 256

        @Override
        String getId() {
            return id
        }

        @Override
        AeadResult encrypt(AeadRequest request) throws SecurityException {
            return null
        }

        @Override
        Message<byte[]> decrypt(DecryptAeadRequest request) throws SecurityException {
            return null
        }

        @Override
        SecretKeyBuilder key() {
            return null
        }

        @Override
        int getKeyBitLength() {
            return keyBitLength
        }
    }

    static class TestKeyAlgorithm implements KeyAlgorithm {

        String id
        int keyBitLength = 256

        @Override
        String getId() {
            return id
        }

        @Override
        KeyResult getEncryptionKey(KeyRequest request) throws SecurityException {
            return null
        }

        @Override
        SecretKey getDecryptionKey(DecryptionKeyRequest request) throws SecurityException {
            return null
        }
    }

    static class TestMacAlgorithm implements MacAlgorithm {

        String id

        @Override
        String getId() {
            return id
        }

        @Override
        byte[] digest(SecureRequest<byte[], SecretKey> request) throws SecurityException {
            return new byte[0]
        }

        @Override
        boolean verify(VerifySecureDigestRequest<SecretKey> request) throws SecurityException {
            return false
        }

        @Override
        SecretKeyBuilder key() {
            return null
        }

        @Override
        int getKeyBitLength() {
            return 0
        }
    }
}
