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
import io.jsonwebtoken.CompressionCodecs
import io.jsonwebtoken.CompressionException
import io.jsonwebtoken.impl.DefaultHeader
import io.jsonwebtoken.impl.io.FakeServiceDescriptorClassLoader
import io.jsonwebtoken.impl.lang.Services
import org.junit.Assert
import org.junit.Test

import static org.hamcrest.CoreMatchers.*
import static org.hamcrest.MatcherAssert.assertThat

class DefaultCompressionCodecResolverTest {

    @Test
    void resolveHeaderTest() {
        assertThat new DefaultCompressionCodecResolver().resolveCompressionCodec(
                new DefaultHeader()), nullValue()
        assertThat new DefaultCompressionCodecResolver().resolveCompressionCodec(
                new DefaultHeader().setCompressionAlgorithm("def")), is(CompressionCodecs.DEFLATE)
        assertThat new DefaultCompressionCodecResolver().resolveCompressionCodec(
                new DefaultHeader().setCompressionAlgorithm("gzip")), is(CompressionCodecs.GZIP)
    }

    @Test
    void invalidCompressionNameTest() {
        try {
            new DefaultCompressionCodecResolver().resolveCompressionCodec(
                    new DefaultHeader().setCompressionAlgorithm("expected-missing"))
            Assert.fail("Expected CompressionException to be thrown")
        } catch (CompressionException e) {
            assertThat e.message, is(String.format(DefaultCompressionCodecResolver.MISSING_COMPRESSION_MESSAGE, "expected-missing"))
        }
    }

    @Test
    void overrideDefaultCompressionImplTest() {
        FakeServiceDescriptorClassLoader.runWithFake "io.jsonwebtoken.io.compression.CompressionCodec.test.override", {

            // first make sure the service loader actually resolves the test class
            assertThat Services.loadAll(CompressionCodec), hasItem(instanceOf(YagCompressionCodec))

            // now we know the class is loadable, make sure we ALWAYS return the GZIP impl
            assertThat new DefaultCompressionCodecResolver().byName("gzip"), instanceOf(GzipCompressionCodec)
        }
    }

    @Test
    void emptyCompressionAlgInHeaderTest() {
        //noinspection GroovyUnusedCatchParameter
        try {
            new DefaultCompressionCodecResolver().byName("")
            Assert.fail("Expected IllegalArgumentException to be thrown")
        } catch (IllegalArgumentException e) {
            // expected
        }
    }
}
