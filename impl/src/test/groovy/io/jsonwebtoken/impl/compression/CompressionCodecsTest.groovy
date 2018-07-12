package io.jsonwebtoken.impl.compression

import org.junit.Test

import static org.junit.Assert.assertSame

@Deprecated //remove just prior to 1.0.0 release
class CompressionCodecsTest {

    @Test
    void testDeflate() {
        def codec = CompressionCodecs.DEFLATE
        assertSame io.jsonwebtoken.CompressionCodecs.DEFLATE, codec
    }

    @Test
    void testGip() {
        def codec = CompressionCodecs.GZIP
        assertSame io.jsonwebtoken.CompressionCodecs.GZIP, codec
    }
}
