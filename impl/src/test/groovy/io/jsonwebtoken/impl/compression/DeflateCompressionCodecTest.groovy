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

import io.jsonwebtoken.CompressionException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import org.junit.Test

import static org.junit.Assert.assertNotSame

/**
 * @since 0.10.8
 */
class DeflateCompressionCodecTest {

    /**
     * Test case for <a href="https://github.com/jwtk/jjwt/issues/536">Issue 536</a>.
     */
    @Test
    void testBackwardsCompatibility_0_10_6() {
        final String jwtFrom0106 = 'eyJhbGciOiJub25lIiwiemlwIjoiREVGIn0.eNqqVsosLlayUspNVdJRKi5NAjJLi1OLgJzMxBIlK0sTMzMLEwsDAx2l1IoCJSsTQwMjExOQQC0AAAD__w.'
        Jwts.parser().enableUnsecured().enableUnsecuredDecompression().build().parseClaimsJwt(jwtFrom0106) // no exception should be thrown
    }

    /**
     * Test to ensure that, even if the backwards-compatibility fallback method throws an exception, that the first
     * one is retained/re-thrown to reflect the correct/expected implementation.
     */
    @Test
    void testBackwardsCompatibilityRetainsFirstIOException() {

        final String compressedFrom0_10_6 = 'eNqqVsosLlayUspNVdJRKi5NAjJLi1OLgJzMxBIlK0sTMzMLEwsDAx2l1IoCJSsTQwMjExOQQC0AAAD__w'
        byte[] invalid = Decoders.BASE64URL.decode(compressedFrom0_10_6)

        IOException unexpected = new IOException("foo")

        def codec = new DeflateCompressionAlgorithm() {
            @Override
            byte[] doDecompressBackCompat(byte[] compressed) throws IOException {
                throw unexpected
            }
        }

        try {
            codec.decompress(invalid)
        } catch (CompressionException ce) {
            assertNotSame(unexpected, ce.getCause())
        }
    }
}
