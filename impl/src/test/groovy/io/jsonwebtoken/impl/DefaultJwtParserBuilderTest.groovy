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
import org.hamcrest.CoreMatchers
import org.junit.Before
import org.junit.Test

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
        assertSame decoder, b.base64UrlDecoder
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
        def key = alg.keyBuilder().build()

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

    static class TestCompressionCodec implements CompressionCodec {

        String id

        @Override
        String getAlgorithmName() {
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
        String getId() {
            return this.id
        }
    }
}
