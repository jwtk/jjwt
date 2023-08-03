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
package io.jsonwebtoken.impl.compression

import io.jsonwebtoken.CompressionCodec
import io.jsonwebtoken.CompressionException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.DefaultHeader
import io.jsonwebtoken.impl.DefaultJwsHeader
import io.jsonwebtoken.impl.io.FakeServiceDescriptorClassLoader
import io.jsonwebtoken.impl.lang.Services
import org.junit.Assert
import org.junit.Before
import org.junit.Test

import static org.hamcrest.CoreMatchers.*
import static org.hamcrest.MatcherAssert.assertThat

class DefaultCompressionCodecResolverTest {

    private DefaultCompressionCodecResolver resolver

    @Before
    void setUp() {
        this.resolver = new DefaultCompressionCodecResolver()
    }

    @Test
    void resolveHeaderTest() {
        assertThat resolver.resolveCompressionCodec(new DefaultHeader([:])), nullValue()
        assertThat resolver.resolveCompressionCodec(new DefaultHeader([zip: 'def'])), is(Jwts.ZIP.DEF)
        assertThat resolver.resolveCompressionCodec(new DefaultHeader([zip: 'gzip'])), is(Jwts.ZIP.GZIP)
    }

    @Test
    void invalidCompressionNameTest() {
        try {
            resolver.resolveCompressionCodec(new DefaultHeader([zip: 'expected-missing']))
            Assert.fail("Expected CompressionException to be thrown")
        } catch (CompressionException e) {
            assertThat e.message, is(String.format(DefaultCompressionCodecResolver.MISSING_COMPRESSION_MESSAGE, "expected-missing"))
        }
    }

    @Test
    void testCustomCompressionCodecServiceDoesNotOverrideStandardCodecs() {
        FakeServiceDescriptorClassLoader.runWithFake "io.jsonwebtoken.io.compression.CompressionCodec.test.override", {

            // first make sure the service loader actually resolves the test class
            assertThat Services.loadAll(CompressionCodec), hasItem(instanceOf(YagCompressionCodec))

            def header = new DefaultJwsHeader(['zip': 'gzip'])
            // now we know the class is loadable, make sure we ALWAYS return the GZIP impl
            assertThat resolver.locate(header), instanceOf(GzipCompressionCodec)
        }
    }
}
